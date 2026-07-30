package core

// AttributeType is the data type of an attribute, per RFC 7643, Section 7.
type AttributeType string

const (
	TypeString    AttributeType = "string"
	TypeBoolean   AttributeType = "boolean"
	TypeDecimal   AttributeType = "decimal"
	TypeInteger   AttributeType = "integer"
	TypeDateTime  AttributeType = "dateTime"
	TypeReference AttributeType = "reference"
	TypeComplex   AttributeType = "complex"
)

// Mutability states when an attribute may be (re)defined.
type Mutability string

const (
	MutabilityReadOnly  Mutability = "readOnly"
	MutabilityReadWrite Mutability = "readWrite"
	MutabilityImmutable Mutability = "immutable"
	MutabilityWriteOnly Mutability = "writeOnly"
)

// Returned states when an attribute is included in a response.
type Returned string

const (
	ReturnedAlways  Returned = "always"
	ReturnedNever   Returned = "never"
	ReturnedDefault Returned = "default"
	ReturnedRequest Returned = "request"
)

// Uniqueness states how the service provider enforces uniqueness.
type Uniqueness string

const (
	UniquenessNone   Uniqueness = "none"
	UniquenessServer Uniqueness = "server"
	UniquenessGlobal Uniqueness = "global"
)

// Attribute describes one attribute of a schema, per RFC 7643, Section 7.
type Attribute struct {
	Name          string        `json:"name"`
	Type          AttributeType `json:"type"`
	MultiValued   bool          `json:"multiValued"`
	Description   string        `json:"description"`
	Required      bool          `json:"required"`
	CaseExact     bool          `json:"caseExact"`
	Mutability    Mutability    `json:"mutability"`
	Returned      Returned      `json:"returned"`
	Uniqueness    Uniqueness    `json:"uniqueness"`
	SubAttributes []*Attribute  `json:"subAttributes,omitempty"`
}

// NewAttribute returns an attribute carrying the characteristic defaults
// RFC 7643, Section 7 declares: readWrite mutability, default returnability
// and no uniqueness. The As* and With modifiers state the deviations.
func NewAttribute(name string, attributeType AttributeType, description string) *Attribute {
	return &Attribute{
		Name:        name,
		Type:        attributeType,
		Description: description,
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
	}
}

func (a *Attribute) AsRequired() *Attribute {
	a.Required = true
	return a
}

func (a *Attribute) AsMultiValued() *Attribute {
	a.MultiValued = true
	return a
}

func (a *Attribute) AsCaseExact() *Attribute {
	a.CaseExact = true
	return a
}

func (a *Attribute) UniqueOn(uniqueness Uniqueness) *Attribute {
	a.Uniqueness = uniqueness
	return a
}

func (a *Attribute) With(subAttributes ...*Attribute) *Attribute {
	a.SubAttributes = subAttributes
	return a
}
