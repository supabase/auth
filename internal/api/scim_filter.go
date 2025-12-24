package api

import (
	"fmt"
	"strings"

	filter "github.com/scim2/filter-parser/v2"
	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/models"
)

type SCIMFilterResult struct {
	Where string
	Args  []interface{}
}

var SCIMUserFilterAttrs = map[string]string{
	"username":     "COALESCE(i.identity_data->>'user_name', u.email)",
	"externalid":   "i.provider_id",
	"email":        "u.email",
	"emails.value": "u.email",
}

var SCIMGroupFilterAttrs = map[string]string{
	"displayname": "display_name",
	"externalid":  "external_id",
}

func ParseSCIMFilterToSQL(filterStr string, allowedAttrs map[string]string) (*SCIMFilterResult, error) {
	if filterStr == "" {
		return &SCIMFilterResult{Where: "1=1", Args: nil}, nil
	}

	expr, err := filter.ParseFilter([]byte(filterStr))
	if err != nil {
		return nil, apierrors.NewSCIMBadRequestError(
			fmt.Sprintf("Invalid filter syntax: %v", err), "invalidFilter")
	}

	return exprToSQL(expr, allowedAttrs)
}

func exprToSQL(expr filter.Expression, allowedAttrs map[string]string) (*SCIMFilterResult, error) {
	switch e := expr.(type) {
	case *filter.AttributeExpression:
		return attrExprToSQL(*e, allowedAttrs)
	case *filter.LogicalExpression:
		return logicalExprToSQL(*e, allowedAttrs)
	case *filter.NotExpression:
		return notExprToSQL(*e, allowedAttrs)
	case *filter.ValuePath:
		return valuePathToSQL(*e, allowedAttrs)
	default:
		return nil, apierrors.NewSCIMBadRequestError(
			fmt.Sprintf("Unsupported filter expression type: %T", expr), "invalidFilter")
	}
}

func attrExprToSQL(e filter.AttributeExpression, allowedAttrs map[string]string) (*SCIMFilterResult, error) {
	attrName := strings.ToLower(e.AttributePath.AttributeName)
	if e.AttributePath.SubAttribute != nil {
		attrName = attrName + "." + strings.ToLower(*e.AttributePath.SubAttribute)
	}

	dbColumn, ok := allowedAttrs[attrName]
	if !ok {
		return nil, apierrors.NewSCIMBadRequestError(
			fmt.Sprintf("Filtering on attribute '%s' is not supported", attrName), "invalidFilter")
	}

	switch e.Operator {
	case filter.EQ:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("LOWER(CAST(%s AS TEXT)) = LOWER(?)", dbColumn),
			Args:  []interface{}{fmt.Sprintf("%v", e.CompareValue)},
		}, nil

	case filter.NE:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("LOWER(CAST(%s AS TEXT)) != LOWER(?)", dbColumn),
			Args:  []interface{}{fmt.Sprintf("%v", e.CompareValue)},
		}, nil

	case filter.CO:
		val, ok := e.CompareValue.(string)
		if !ok {
			return nil, apierrors.NewSCIMBadRequestError("'co' operator requires a string value", "invalidValue")
		}
		return &SCIMFilterResult{
			Where: fmt.Sprintf("LOWER(CAST(%s AS TEXT)) LIKE LOWER(?)", dbColumn),
			Args:  []interface{}{"%" + escapeLikePattern(val) + "%"},
		}, nil

	case filter.SW:
		val, ok := e.CompareValue.(string)
		if !ok {
			return nil, apierrors.NewSCIMBadRequestError("'sw' operator requires a string value", "invalidValue")
		}
		return &SCIMFilterResult{
			Where: fmt.Sprintf("LOWER(CAST(%s AS TEXT)) LIKE LOWER(?)", dbColumn),
			Args:  []interface{}{escapeLikePattern(val) + "%"},
		}, nil

	case filter.EW:
		val, ok := e.CompareValue.(string)
		if !ok {
			return nil, apierrors.NewSCIMBadRequestError("'ew' operator requires a string value", "invalidValue")
		}
		return &SCIMFilterResult{
			Where: fmt.Sprintf("LOWER(CAST(%s AS TEXT)) LIKE LOWER(?)", dbColumn),
			Args:  []interface{}{"%" + escapeLikePattern(val)},
		}, nil

	case filter.PR:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("(%s IS NOT NULL AND CAST(%s AS TEXT) != '')", dbColumn, dbColumn),
			Args:  nil,
		}, nil

	case filter.GT:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("%s > ?", dbColumn),
			Args:  []interface{}{e.CompareValue},
		}, nil

	case filter.GE:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("%s >= ?", dbColumn),
			Args:  []interface{}{e.CompareValue},
		}, nil

	case filter.LT:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("%s < ?", dbColumn),
			Args:  []interface{}{e.CompareValue},
		}, nil

	case filter.LE:
		return &SCIMFilterResult{
			Where: fmt.Sprintf("%s <= ?", dbColumn),
			Args:  []interface{}{e.CompareValue},
		}, nil

	default:
		return nil, apierrors.NewSCIMBadRequestError(
			fmt.Sprintf("Unsupported operator: %s", e.Operator), "invalidFilter")
	}
}

func logicalExprToSQL(e filter.LogicalExpression, allowedAttrs map[string]string) (*SCIMFilterResult, error) {
	left, err := exprToSQL(e.Left, allowedAttrs)
	if err != nil {
		return nil, err
	}

	right, err := exprToSQL(e.Right, allowedAttrs)
	if err != nil {
		return nil, err
	}

	op := "AND"
	if e.Operator == filter.OR {
		op = "OR"
	}

	return &SCIMFilterResult{
		Where: fmt.Sprintf("(%s %s %s)", left.Where, op, right.Where),
		Args:  append(left.Args, right.Args...),
	}, nil
}

func notExprToSQL(e filter.NotExpression, allowedAttrs map[string]string) (*SCIMFilterResult, error) {
	operand, err := exprToSQL(e.Expression, allowedAttrs)
	if err != nil {
		return nil, err
	}

	return &SCIMFilterResult{
		Where: fmt.Sprintf("NOT (%s)", operand.Where),
		Args:  operand.Args,
	}, nil
}

// valuePathToSQL handles bracket notation (e.g., emails[value eq "x"]).
// Only emails[value ...] is supported since Supabase Auth stores one email per user.
func valuePathToSQL(e filter.ValuePath, allowedAttrs map[string]string) (*SCIMFilterResult, error) {
	attrName := strings.ToLower(e.AttributePath.AttributeName)

	switch attrName {
	case "emails":
		if e.ValueFilter != nil {
			if attrExpr, ok := e.ValueFilter.(*filter.AttributeExpression); ok {
				if strings.ToLower(attrExpr.AttributePath.AttributeName) == "value" {
					modifiedExpr := filter.AttributeExpression{
						AttributePath: filter.AttributePath{AttributeName: "email"},
						Operator:      attrExpr.Operator,
						CompareValue:  attrExpr.CompareValue,
					}
					return attrExprToSQL(modifiedExpr, allowedAttrs)
				}
			}
		}
	}

	return nil, apierrors.NewSCIMBadRequestError(
		fmt.Sprintf("Value path filter '%s[...]' is not supported", attrName), "invalidFilter")
}

func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

func toModelFilterClause(f *SCIMFilterResult) *models.SCIMFilterClause {
	if f == nil {
		return nil
	}
	return &models.SCIMFilterClause{
		Where: f.Where,
		Args:  f.Args,
	}
}
