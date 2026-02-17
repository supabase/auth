package utilities

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// Version is git commit or release tag from which this binary was built.
var Version string

func InitVersionMetrics(ctx context.Context) error {
	return initVersionMetrics(ctx, Version)
}

func initVersionMetrics(ctx context.Context, ver string) error {
	vi, err := parseSemver(ver)
	if err != nil {
		vi = &versionInfo{}
	}

	if err := initMetrics(ctx, vi); err != nil {
		return err
	}
	return nil
}

func initGauge(ctx context.Context, typ string, val uint64) error {
	name := fmt.Sprintf("global_auth_version_%v", typ)
	desc := fmt.Sprintf("Set to this auth servers %v version number.", typ)

	g, err := otel.Meter("gotrue").Int64Gauge(name, metric.WithDescription(desc))
	if err != nil {
		return err
	}
	if val > math.MaxInt64 {
		return errors.New("value is > math.MaxInt64")
	}

	g.Record(ctx, int64(val))
	return nil
}

func initMetrics(ctx context.Context, vi *versionInfo) error {
	return errors.Join(
		initGauge(ctx, "major", vi.Major),
		initGauge(ctx, "minor", vi.Minor),
		initGauge(ctx, "patch", vi.Patch),
		initGauge(ctx, "rc", vi.RC),
	)
}

type versionInfo struct {
	Original string
	Major    uint64
	Minor    uint64
	Patch    uint64
	RC       uint64
}

func parseSemver(ver string) (*versionInfo, error) {
	vi := &versionInfo{
		Original: ver,
	}

	ver = normalizeVersion(ver)
	sv, err := semver.NewVersion(ver)
	if err != nil {
		return nil, err
	}

	pre := sv.Prerelease()
	if strings.HasPrefix(pre, "rc") {
		pre = strings.TrimPrefix(pre, "rc.")
		pre = strings.TrimPrefix(pre, "rc-")
		pre = strings.TrimPrefix(pre, "rc")
		if i := strings.IndexByte(pre, '-'); i >= 0 {
			pre = pre[:i]
		}
		if i := strings.IndexByte(pre, '.'); i >= 0 {
			pre = pre[:i]
		}

		rc, err := strconv.ParseUint(pre, 10, 64)
		if err == nil {
			vi.RC = rc
		}
	}

	vi.Major = sv.Major()
	vi.Minor = sv.Minor()
	vi.Patch = sv.Patch()
	return vi, nil
}

func normalizeVersion(ver string) string {
	ver = strings.TrimSpace(ver)
	if strings.HasPrefix(ver, "v") {
		return ver
	}
	if strings.HasPrefix(ver, "rc") {
		return "v" + ver[2:]
	}
	return "v" + ver
}
