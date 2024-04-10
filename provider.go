package libdnstemplate

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
	"strconv"

	"github.com/libdns/libdns"
)

type Provider struct {
	Host string `json:"host,omitempty"`
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

func (p *Provider) sendCommand(conn net.Conn, command string) (string, error) {
	_, err := conn.Write([]byte(command + "\n"))
	if err != nil {
		return "", err
	}

	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	response := string(buffer[:n])
	return response, nil
}

func (p *Provider) connect() (net.Conn, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", p.Host, 7070))
	if err != nil {
		return nil, err
	}

	// Skip the initial banner message
	_, err = p.sendCommand(conn, "")
	if err != nil {
		conn.Close()
		return nil, err
	}

	// Log in
	response, err := p.sendCommand(conn, fmt.Sprintf("LOGIN %s %s", p.User, p.Pass))
	if err != nil || !strings.Contains(response, "225") {
		conn.Close()
		return nil, fmt.Errorf("login failed: %s", response)
	}

	return conn, nil
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Adjust command as necessary based on actual requirements
	response, err := p.sendCommand(conn, fmt.Sprintf("LISTRR %s", zone))
	if err != nil {
		return nil, err
	}

	lines := strings.Split(response, "\n")
	var records []libdns.Record
	for _, line := range lines {
		if !strings.HasPrefix(line, "151") {
			continue
		}

		parts := strings.Fields(line[4:])
		if len(parts) < 3 {
			continue // Not enough parts to form a record
		}

		domain := parts[0]
		recordType := parts[1]
		// The value and TTL/priority are combined in the last part for some records
		valueAndTTL := parts[len(parts)-1]
		valueParts := strings.Split(valueAndTTL, ":")
		value := valueParts[0]
		ttl := time.Duration(0)
		if len(valueParts) > 1 {
			ttlSeconds, err := strconv.Atoi(valueParts[1])
			if err == nil {
				ttl = time.Duration(ttlSeconds) * time.Second
			}
		}

		// Handling for MX and SRV records which have an additional priority or priority + weight + port
		if recordType == "MX" && len(parts) == 4 {
			// MX records include a priority in the value
			value = parts[2]
		} else if recordType == "SRV" && len(parts) >= 6 {
			// SRV records have a more complex format
			value = fmt.Sprintf("%s %s %s %s", parts[2], parts[3], parts[4], parts[5])
			if len(parts) == 7 {
				// Handle potential SRV TTL
				valueAndTTL = parts[6]
				valueParts = strings.Split(valueAndTTL, ":")
				if len(valueParts) > 1 {
					ttlSeconds, err := strconv.Atoi(valueParts[1])
					if err == nil {
						ttl = time.Duration(ttlSeconds) * time.Second
					}
				}
			}
		}

		record := libdns.Record{
			Type:  recordType,
			Name:  domain,
			Value: value,
			TTL:   ttl,
		}
		records = append(records, record)
	}

	return records, nil
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var addedRecords []libdns.Record
	for _, record := range records {
		command := fmt.Sprintf("ADDRR %s %s %s:%d", record.Name, record.Type, record.Value, record.TTL.Seconds())
		_, err := p.sendCommand(conn, command)
		if err != nil {
			log.Printf("Failed to add record: %v", err)
			continue
		}

		addedRecords = append(addedRecords, record)
	}

	return addedRecords, nil
}

func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var updatedRecords []libdns.Record
	for _, record := range records {
		// Assuming ADDRR is used for both adding and updating records
		// Special handling for SRV records as an example
		command := fmt.Sprintf("ADDRR %s %s %s", record.Name, record.Type, record.Value)
		if record.Type == "SRV" {
			command = fmt.Sprintf("ADDRR %s %s %s:%d", record.Name, record.Type, record.Value, int(record.TTL.Seconds()))
		}
		if _, err := p.sendCommand(conn, command); err != nil {
			log.Printf("Failed to set record: %v", err)
			continue
		}

		updatedRecords = append(updatedRecords, record)
	}

	return updatedRecords, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	conn, err := p.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var deletedRecords []libdns.Record
	for _, record := range records {
		// The protocol seems to support deleting by host and optionally by record type and target
		command := fmt.Sprintf("DELRR %s %s %s", record.Name, record.Type, record.Value)
		if _, err := p.sendCommand(conn, command); err != nil {
			log.Printf("Failed to delete record: %v", err)
			continue
		}

		deletedRecords = append(deletedRecords, record)
	}

	return deletedRecords, nil
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
