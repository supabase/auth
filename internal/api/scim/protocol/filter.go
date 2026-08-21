package protocol

// Filter is a parsed SCIM filter expression, the FILTER rule of RFC 7644,
// Section 3.4.2.2. It is an abstract syntax tree: parsing says what a filter
// means, and a separate compiler decides which of those meanings a given store
// can serve.
type Filter interface {
	filterNode()
}

// CompareOp is a compareOp of the grammar, plus the "pr" of attrExp. Presence
// is folded in here because it occupies the same position as a comparison, just
// without a value.
type CompareOp string

const (
	OpPresent        CompareOp = "pr"
	OpEqual          CompareOp = "eq"
	OpNotEqual       CompareOp = "ne"
	OpContains       CompareOp = "co"
	OpStartsWith     CompareOp = "sw"
	OpEndsWith       CompareOp = "ew"
	OpGreaterThan    CompareOp = "gt"
	OpLessThan       CompareOp = "lt"
	OpGreaterOrEqual CompareOp = "ge"
	OpLessOrEqual    CompareOp = "le"
)

// LogicalOp joins two filters, the "and"/"or" of logExp.
type LogicalOp string

const (
	LogicalAnd LogicalOp = "and"
	LogicalOr  LogicalOp = "or"
)

// AttrPath names an attribute: [URI ":"] ATTRNAME *1subAttr. URI is empty unless
// the client qualified the name with a schema URI; Sub is empty unless it named
// a sub-attribute of a complex attribute.
type AttrPath struct {
	URI  string
	Name string
	Sub  string
}

// Value is a compValue: a JSON scalar. Raw holds it decoded, so a string is a
// string, a number is a float64, a boolean is a bool, and null is nil -- which
// is what lets a compiler bind it as a parameter of the right type.
type Value struct {
	Raw any
}

// AttrExpr is an attrExp: an attribute tested for presence (Op is OpPresent and
// Value is unused) or compared against a value.
type AttrExpr struct {
	Path  AttrPath
	Op    CompareOp
	Value Value
}

// LogicalExpr is a logExp: two filters joined by "and" or "or".
type LogicalExpr struct {
	Op    LogicalOp
	Left  Filter
	Right Filter
}

// NotExpr is the "not" "(" FILTER ")" of the grammar: a negated filter.
type NotExpr struct {
	Inner Filter
}

// ValuePath is a valuePath: a filter over the sub-attributes of a parent
// attribute, as in emails[type eq "work"].
type ValuePath struct {
	Path   AttrPath
	Filter Filter
}

func (*AttrExpr) filterNode()    {}
func (*LogicalExpr) filterNode() {}
func (*NotExpr) filterNode()     {}
func (*ValuePath) filterNode()   {}
