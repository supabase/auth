package models

import (
	"bytes"
	"strconv"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// ParseSAMLMetadata parses IdP metadata, including documents whose root is
// EntitiesDescriptor. crewjam/saml v0.4.14 unmarshals that wrapper's
// cacheDuration into a time.Duration, which encoding/xml reads with
// strconv.ParseInt. A spec-valid value such as PT5H then fails the whole
// document. EntityDescriptor already decodes xs:duration, so only the
// wrapper attribute is removed before parsing. The stored XML is unchanged.
func ParseSAMLMetadata(raw []byte) (*saml.EntityDescriptor, error) {
	return samlsp.ParseMetadata(withoutEntitiesDescriptorXSCacheDuration(raw))
}

// withoutEntitiesDescriptorXSCacheDuration drops cacheDuration attributes on
// EntitiesDescriptor start tags when the value is not an integer. Other
// elements, including EntityDescriptor, are left byte for byte.
func withoutEntitiesDescriptorXSCacheDuration(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	i := 0
	for i < len(raw) {
		if raw[i] != '<' {
			out = append(out, raw[i])
			i++
			continue
		}
		if bytes.HasPrefix(raw[i:], []byte("<!--")) {
			end := bytes.Index(raw[i:], []byte("-->"))
			if end < 0 {
				out = append(out, raw[i:]...)
				return out
			}
			end += len("-->")
			out = append(out, raw[i:i+end]...)
			i += end
			continue
		}
		if bytes.HasPrefix(raw[i:], []byte("<![CDATA[")) {
			end := bytes.Index(raw[i:], []byte("]]>"))
			if end < 0 {
				out = append(out, raw[i:]...)
				return out
			}
			end += len("]]>")
			out = append(out, raw[i:i+end]...)
			i += end
			continue
		}
		if i+1 < len(raw) && (raw[i+1] == '/' || raw[i+1] == '?' || raw[i+1] == '!') {
			end := xmlTagEnd(raw, i)
			out = append(out, raw[i:end]...)
			i = end
			continue
		}

		end := xmlTagEnd(raw, i)
		tag := raw[i:end]
		if xmlStartTagLocalName(tag) == "EntitiesDescriptor" {
			tag = dropNonIntegerCacheDuration(tag)
		}
		out = append(out, tag...)
		i = end
	}
	return out
}

func xmlTagEnd(raw []byte, i int) int {
	quote := byte(0)
	for j := i + 1; j < len(raw); j++ {
		c := raw[j]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == '>' {
			return j + 1
		}
	}
	return len(raw)
}

func xmlStartTagLocalName(tag []byte) string {
	i := 1
	for i < len(tag) && isXMLSpace(tag[i]) {
		i++
	}
	start := i
	for i < len(tag) && !isXMLSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}
	name := tag[start:i]
	if idx := bytes.LastIndexByte(name, ':'); idx >= 0 {
		name = name[idx+1:]
	}
	return string(name)
}

func dropNonIntegerCacheDuration(tag []byte) []byte {
	out := make([]byte, 0, len(tag))
	i := 0
	for i < len(tag) && !isXMLSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		out = append(out, tag[i])
		i++
	}
	for i < len(tag) {
		if tag[i] == '>' || (tag[i] == '/' && i+1 < len(tag) && tag[i+1] == '>') {
			out = append(out, tag[i:]...)
			return out
		}
		if !isXMLSpace(tag[i]) {
			out = append(out, tag[i:]...)
			return out
		}
		ws := i
		for i < len(tag) && isXMLSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] == '>' || tag[i] == '/' {
			out = append(out, tag[ws:]...)
			return out
		}
		nameStart := i
		for i < len(tag) && tag[i] != '=' && !isXMLSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
			i++
		}
		name := tag[nameStart:i]
		for i < len(tag) && isXMLSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] != '=' {
			out = append(out, tag[ws:]...)
			return out
		}
		i++
		for i < len(tag) && isXMLSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || (tag[i] != '"' && tag[i] != '\'') {
			out = append(out, tag[ws:]...)
			return out
		}
		quote := tag[i]
		i++
		valStart := i
		for i < len(tag) && tag[i] != quote {
			i++
		}
		if i >= len(tag) {
			out = append(out, tag[ws:]...)
			return out
		}
		val := tag[valStart:i]
		i++
		local := name
		if idx := bytes.LastIndexByte(name, ':'); idx >= 0 {
			local = name[idx+1:]
		}
		if bytes.Equal(local, []byte("cacheDuration")) {
			if _, err := strconv.ParseInt(string(val), 10, 64); err != nil {
				continue
			}
		}
		out = append(out, tag[ws:i]...)
	}
	return out
}

func isXMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
