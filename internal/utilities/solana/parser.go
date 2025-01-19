package siws

import (
	"strings"
	"time"
)

func ParseSIWSMessage(raw string) (*SIWSMessage, error) {
    lines := strings.Split(raw, "\n")
    
    // Remove empty lines at the end
    var cleaned []string
    for _, line := range lines {
        l := strings.TrimSpace(line)
        if l != "" {
            cleaned = append(cleaned, l)
        }
    }

    if len(cleaned) < 2 {
        return nil, ErrorMalformedMessage
    }

    // Parse domain line
    matches := strings.Split(cleaned[0], " wants you to sign in with your Solana account:")
    if len(matches) != 2 || matches[0] == "" {
        return nil, ErrInvalidDomainFormat
    }
    domain := matches[0]

    // Parse address line
    address := strings.TrimSpace(cleaned[1])
    
    // Initialize message struct
    msg := &SIWSMessage{
        Domain:    domain,
        Address:   address,
    }

    // Parse optional statement - must be preceded by double newline
    lineIndex := 2
    if lineIndex+1 < len(cleaned) {
        for i := 2; i < len(lines)-1; i++ {
            if lines[i] == "" && lines[i+1] != "" && 
               !strings.Contains(lines[i+1], ": ") {
                msg.Statement = cleaned[lineIndex+1]
                lineIndex = lineIndex + 2
                break
            }
        }
    }

    // Parse key-value fields
    for lineIndex < len(cleaned) {
        line := cleaned[lineIndex]
        
        switch {
        case strings.HasPrefix(line, "URI: "):
            msg.URI = strings.TrimSpace(strings.TrimPrefix(line, "URI:"))
            
        case strings.HasPrefix(line, "Version: "):
            msg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
            
        case strings.HasPrefix(line, "Chain ID: "):
            msg.ChainID = strings.TrimSpace(strings.TrimPrefix(line, "Chain ID:"))
            
        case strings.HasPrefix(line, "Nonce: "):
            msg.Nonce = strings.TrimSpace(strings.TrimPrefix(line, "Nonce:"))
            
        case strings.HasPrefix(line, "Issued At: "):
            tsString := strings.TrimSpace(strings.TrimPrefix(line, "Issued At:"))
            ts, err := time.Parse(time.RFC3339, tsString)
            if err != nil {
                return nil, ErrInvalidIssuedAtFormat
            }
            msg.IssuedAt = ts
            
        case strings.HasPrefix(line, "Expiration Time: "):
            tsString := strings.TrimSpace(strings.TrimPrefix(line, "Expiration Time:"))
            ts, err := time.Parse(time.RFC3339, tsString)
            if err != nil {
                return nil, ErrInvalidExpirationTimeFormat
            }
            msg.ExpirationTime = ts
            
        case strings.HasPrefix(line, "Not Before: "):
            tsString := strings.TrimSpace(strings.TrimPrefix(line, "Not Before:"))
            ts, err := time.Parse(time.RFC3339, tsString)
            if err != nil {
                return nil, ErrInvalidNotBeforeFormat
            }
            msg.NotBefore = ts
            
        case strings.HasPrefix(line, "Request ID: "):
            msg.RequestID = strings.TrimSpace(strings.TrimPrefix(line, "Request ID:"))
            
        case strings.HasPrefix(line, "Resources:"):
            lineIndex++
            for lineIndex < len(cleaned) {
                resourceLine := cleaned[lineIndex]
                if !strings.HasPrefix(resourceLine, "- ") {
                    break
                }
                resource := strings.TrimSpace(strings.TrimPrefix(resourceLine, "-"))
                msg.Resources = append(msg.Resources, resource)
                lineIndex++
            }
            continue
            
        default:
            return nil, ErrUnrecognizedLine
        }
        lineIndex++
    }

    return msg, nil
}

