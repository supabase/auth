package apierrors

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// TODO(cstockton): Don't like how these are global variables here. I think we
// should probably have a metrics package which is initialized before the api
// server is created and then passed in as an option to the *API.
var (
	errorCodeCounter     metric.Int64Counter
	errorCodeAttrsByCode = make(map[string]metric.MeasurementOption)
)

func RecordErrorCode(ctx context.Context, errorCode ErrorCode) {
	attrs, ok := errorCodeAttrsByCode[errorCode]
	if !ok {
		attrs = errorCodeAttrsByCode[ErrorCodeUnknown]
	}
	errorCodeCounter.Add(ctx, 1, attrs)
}

func RecordPostgresCode(ctx context.Context, code string) {
	attrs := metric.WithAttributeSet(
		attribute.NewSet(
			attribute.String("type", "postgres"),
			attribute.String("error", code),
		),
	)
	errorCodeCounter.Add(ctx, 1, attrs)
}

func InitMetrics() error {
	return initMetrics(errorCodesMap)
}

func initMetrics(ecm map[string]string) error {
	if len(errorCodesMap) == 0 {
		const msg = "InitMetrics: errorCodesMap is empty"
		return errors.New(msg)
	}

	counter, err := otel.Meter("gotrue").Int64Counter(
		"global_auth_errors_total",
		metric.WithDescription("Number of error codes returned by type and error."),
		metric.WithUnit("{type}"),
		metric.WithUnit("{error}"),
	)
	if err != nil {
		return fmt.Errorf("InitMetrics: %w", err)
	}

	// TODO(cstockton): I'm not sure about having a single dimension of
	// "error_code", as I begin trying to dig into the types of errors we
	// raise I might want to add a type specifier. For example OAuthError does
	// not have an auth error code, but may wrap one internally.
	//
	// This is really about deciding how to strike the balance between caller
	// burden and best effort inferrence like we are doing here.
	errorCodeAttrsByCode[ErrorCodeUnknown] = metric.WithAttributes(
		attribute.String("error_code", ErrorCodeUnknown),
	)
	for code := range ecm {
		attrs := metric.WithAttributeSet(
			attribute.NewSet(
				attribute.String("type", "api"),
				attribute.String("error", code),
			),
		)
		errorCodeAttrsByCode[code] = attrs
	}

	errorCodeCounter = counter
	return nil
}
