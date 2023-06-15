package skipper

import (
	"net/http"
	"strings"

	"gateway-service/log"

	ot "github.com/opentracing/opentracing-go"
	"github.com/zalando/skipper"
	"github.com/zalando/skipper/dataclients/routestring"
	"github.com/zalando/skipper/eskipfile"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/auth"
	"github.com/zalando/skipper/filters/builtin"
	"github.com/zalando/skipper/metrics"
	"github.com/zalando/skipper/proxy"
	"github.com/zalando/skipper/routing"
	"github.com/zalando/skipper/secrets"
	"github.com/zalando/skipper/tracing"

	pauth "github.com/zalando/skipper/predicates/auth"
	"github.com/zalando/skipper/predicates/content"
	"github.com/zalando/skipper/predicates/cookie"
	"github.com/zalando/skipper/predicates/cron"
	"github.com/zalando/skipper/predicates/forwarded"
	"github.com/zalando/skipper/predicates/host"
	"github.com/zalando/skipper/predicates/interval"
	"github.com/zalando/skipper/predicates/methods"
	"github.com/zalando/skipper/predicates/primitive"
	"github.com/zalando/skipper/predicates/query"
	"github.com/zalando/skipper/predicates/source"
	"github.com/zalando/skipper/predicates/tee"
	"github.com/zalando/skipper/predicates/traffic"
)

type Options struct {
	skipper.Options
}

type Skipper struct {
	routing        *routing.Routing
	proxy          *proxy.Proxy
	metricsHandler http.Handler
}

// filterRegistry creates a filter registry with the builtin and
// custom filter specs registered excluding disabled filters
func (o *Options) filterRegistry() filters.Registry {
	registry := make(filters.Registry)

	disabledFilters := make(map[string]struct{})
	for _, name := range o.DisabledFilters {
		disabledFilters[name] = struct{}{}
	}

	for _, f := range builtin.Filters() {
		if _, ok := disabledFilters[f.Name()]; !ok {
			registry.Register(f)
		}
	}

	for _, f := range o.CustomFilters {
		if _, ok := disabledFilters[f.Name()]; !ok {
			registry.Register(f)
		}
	}

	return registry
}

func (o *Options) createDataClients() ([]routing.DataClient, error) {
	var clients []routing.DataClient

	if o.RoutesFile != "" {
		for _, rf := range strings.Split(o.RoutesFile, ",") {
			f, err := eskipfile.Open(rf)
			if err != nil {
				log.Error("error while opening eskip file", err)
				return nil, err
			}

			clients = append(clients, f)
		}
	}

	if o.InlineRoutes != "" {
		ir, err := routestring.New(o.InlineRoutes)
		if err != nil {
			log.Error("error while parsing inline routes", err)
			return nil, err
		}

		clients = append(clients, ir)
	}

	return clients, nil
}

func New(o Options) *Skipper {
	// Metrics
	if o.EnablePrometheusMetrics {
		o.MetricsFlavours = append(o.MetricsFlavours, "prometheus")
	}

	metricsKind := metrics.UnkownKind
	for _, s := range o.MetricsFlavours {
		switch s {
		case "codahale":
			metricsKind |= metrics.CodaHaleKind
		case "prometheus":
			metricsKind |= metrics.PrometheusKind
		}
	}

	// set default if unset
	if metricsKind == metrics.UnkownKind {
		metricsKind = metrics.CodaHaleKind
	}

	log.Infof("Expose metrics in %s format", metricsKind)
	mtrOpts := metrics.Options{
		Format:                             metricsKind,
		Prefix:                             o.MetricsPrefix,
		EnableDebugGcMetrics:               o.EnableDebugGcMetrics,
		EnableRuntimeMetrics:               o.EnableRuntimeMetrics,
		EnableServeRouteMetrics:            o.EnableServeRouteMetrics,
		EnableServeRouteCounter:            o.EnableServeRouteCounter,
		EnableServeHostMetrics:             o.EnableServeHostMetrics,
		EnableServeHostCounter:             o.EnableServeHostCounter,
		EnableServeMethodMetric:            o.EnableServeMethodMetric,
		EnableServeStatusCodeMetric:        o.EnableServeStatusCodeMetric,
		EnableBackendHostMetrics:           o.EnableBackendHostMetrics,
		EnableProfile:                      o.EnableProfile,
		BlockProfileRate:                   o.BlockProfileRate,
		MutexProfileFraction:               o.MutexProfileFraction,
		MemProfileRate:                     o.MemProfileRate,
		EnableAllFiltersMetrics:            o.EnableAllFiltersMetrics,
		EnableCombinedResponseMetrics:      o.EnableCombinedResponseMetrics,
		EnableRouteResponseMetrics:         o.EnableRouteResponseMetrics,
		EnableRouteBackendErrorsCounters:   o.EnableRouteBackendErrorsCounters,
		EnableRouteStreamingErrorsCounters: o.EnableRouteStreamingErrorsCounters,
		EnableRouteBackendMetrics:          o.EnableRouteBackendMetrics,
		UseExpDecaySample:                  o.MetricsUseExpDecaySample,
		HistogramBuckets:                   o.HistogramMetricBuckets,
		DisableCompatibilityDefaults:       o.DisableMetricsCompatibilityDefaults,
		PrometheusRegistry:                 o.PrometheusRegistry,
	}

	mtr := o.MetricsBackend
	if mtr == nil {
		mtr = metrics.NewMetrics(mtrOpts)
	}
	metrics.Default = mtr
	metricsHandler := metrics.NewHandler(mtrOpts, mtr)

	// Data Clients
	dataClients, err := o.createDataClients()
	if err != nil {
		return nil //, err
	}

	// Include bundled custom predicates
	o.CustomPredicates = append(o.CustomPredicates,
		source.New(),
		source.NewFromLast(),
		source.NewClientIP(),
		interval.NewBetween(),
		interval.NewBefore(),
		interval.NewAfter(),
		cron.New(),
		cookie.New(),
		query.New(),
		traffic.New(),
		traffic.NewSegment(),
		primitive.NewTrue(),
		primitive.NewFalse(),
		primitive.NewShutdown(),
		pauth.NewJWTPayloadAllKV(),
		pauth.NewJWTPayloadAnyKV(),
		pauth.NewJWTPayloadAllKVRegexp(),
		pauth.NewJWTPayloadAnyKVRegexp(),
		pauth.NewHeaderSHA256(),
		methods.New(),
		tee.New(),
		forwarded.NewForwardedHost(),
		forwarded.NewForwardedProto(),
		host.NewAny(),
		content.NewContentLengthBetween(),
	)

	oauthConfig := &auth.OAuthConfig{}
	if o.EnableOAuth2GrantFlow /* explicitly enable grant flow */ {
		grantSecrets := secrets.NewSecretPaths(o.CredentialsUpdateInterval)
		defer grantSecrets.Close()

		oauthConfig.AuthURL = o.OAuth2AuthURL
		oauthConfig.TokenURL = o.OAuth2TokenURL
		oauthConfig.RevokeTokenURL = o.OAuth2RevokeTokenURL
		oauthConfig.TokeninfoURL = o.OAuthTokeninfoURL
		oauthConfig.SecretFile = o.OAuth2SecretFile
		oauthConfig.ClientID = o.OAuth2ClientID
		oauthConfig.ClientSecret = o.OAuth2ClientSecret
		oauthConfig.ClientIDFile = o.OAuth2ClientIDFile
		oauthConfig.ClientSecretFile = o.OAuth2ClientSecretFile
		oauthConfig.CallbackPath = o.OAuth2CallbackPath
		oauthConfig.AuthURLParameters = o.OAuth2AuthURLParameters
		oauthConfig.SecretsProvider = grantSecrets
		oauthConfig.Secrets = o.SecretsRegistry
		oauthConfig.AccessTokenHeaderName = o.OAuth2AccessTokenHeaderName
		oauthConfig.TokeninfoSubjectKey = o.OAuth2TokeninfoSubjectKey
		oauthConfig.GrantTokeninfoKeys = o.OAuth2GrantTokeninfoKeys
		oauthConfig.TokenCookieName = o.OAuth2TokenCookieName
		oauthConfig.TokenCookieRemoveSubdomains = &o.OAuth2TokenCookieRemoveSubdomains
		oauthConfig.ConnectionTimeout = o.OAuthTokeninfoTimeout
		oauthConfig.MaxIdleConnectionsPerHost = o.IdleConnectionsPerHost
		// oauthConfig.Tracer = tracer

		if err := oauthConfig.Init(); err != nil {
			log.Errorf("Failed to initialize oauth grant filter: %v.", err)
			// return err
		}

		o.CustomFilters = append(o.CustomFilters,
			oauthConfig.NewGrant(),
			oauthConfig.NewGrantCallback(),
			oauthConfig.NewGrantClaimsQuery(),
			oauthConfig.NewGrantLogout(),
		)
	}

	// Custom filters
	if o.OAuthTokeninfoURL != "" {
		tio := auth.TokeninfoOptions{
			URL:          o.OAuthTokeninfoURL,
			Timeout:      o.OAuthTokeninfoTimeout,
			MaxIdleConns: o.IdleConnectionsPerHost,
			// Tracer:       tracer,
			CacheSize: o.OAuthTokeninfoCacheSize,
			CacheTTL:  o.OAuthTokeninfoCacheTTL,
		}

		o.CustomFilters = append(o.CustomFilters,
			auth.NewOAuthTokeninfoAllScopeWithOptions(tio),
			auth.NewOAuthTokeninfoAnyScopeWithOptions(tio),
			auth.NewOAuthTokeninfoAllKVWithOptions(tio),
			auth.NewOAuthTokeninfoAnyKVWithOptions(tio),
		)
	}

	tio := auth.TokenintrospectionOptions{
		Timeout:      o.OAuthTokenintrospectionTimeout,
		MaxIdleConns: o.IdleConnectionsPerHost,
		// Tracer:       tracer,
	}

	o.CustomFilters = append(o.CustomFilters,
		// logfilter.NewAuditLog(o.MaxAuditBody),
		// block.NewBlock(o.MaxMatcherBufferSize),
		// block.NewBlockHex(o.MaxMatcherBufferSize),
		// auth.NewBearerInjector(sp),
		auth.NewJwtValidationWithOptions(tio),
		auth.TokenintrospectionWithOptions(auth.NewOAuthTokenintrospectionAnyClaims, tio),
		auth.TokenintrospectionWithOptions(auth.NewOAuthTokenintrospectionAllClaims, tio),
		auth.TokenintrospectionWithOptions(auth.NewOAuthTokenintrospectionAnyKV, tio),
		auth.TokenintrospectionWithOptions(auth.NewOAuthTokenintrospectionAllKV, tio),
		auth.TokenintrospectionWithOptions(auth.NewSecureOAuthTokenintrospectionAnyClaims, tio),
		auth.TokenintrospectionWithOptions(auth.NewSecureOAuthTokenintrospectionAllClaims, tio),
		auth.TokenintrospectionWithOptions(auth.NewSecureOAuthTokenintrospectionAnyKV, tio),
		auth.TokenintrospectionWithOptions(auth.NewSecureOAuthTokenintrospectionAllKV, tio),
		// auth.WebhookWithOptions(who),
		auth.NewOIDCQueryClaimsFilter(),
		// apiusagemonitoring.NewApiUsageMonitoring(
		// 	o.ApiUsageMonitoringEnable,
		// 	o.ApiUsageMonitoringRealmKeys,
		// 	o.ApiUsageMonitoringClientKeys,
		// 	o.ApiUsageMonitoringRealmsTrackingPattern,
		// ),
		// admissionControlFilter,
	)

	var mo routing.MatchingOptions
	if o.IgnoreTrailingSlash {
		mo = routing.IgnoreTrailingSlash
	}

	ro := routing.Options{
		FilterRegistry:  o.filterRegistry(),
		Predicates:      o.CustomPredicates,
		MatchingOptions: mo,
		DataClients:     dataClients,
		Log:             nil,
		SignalFirstLoad: o.WaitFirstRouteLoad,
	}

	routing := routing.New(ro)
	defer routing.Close()

	// Tracing
	var tracer ot.Tracer
	if len(o.OpenTracing) > 0 {
		tracer, err = tracing.InitTracer(o.OpenTracing)
		if err != nil {
			log.Error("Failed to create tracer", err)
			// return err
		}
	} else {
		// always have a tracer available, so filter authors can rely on the
		// existence of a tracer
		tracer, _ = tracing.LoadTracingPlugin(o.PluginDirs, []string{"noop"})
	}

	proxyParams := proxy.Params{
		Routing:                  routing,
		Flags:                    o.ProxyFlags,
		PriorityRoutes:           o.PriorityRoutes,
		IdleConnectionsPerHost:   o.IdleConnectionsPerHost,
		CloseIdleConnsPeriod:     o.CloseIdleConnsPeriod,
		FlushInterval:            o.BackendFlushInterval,
		ExperimentalUpgrade:      o.ExperimentalUpgrade,
		ExperimentalUpgradeAudit: o.ExperimentalUpgradeAudit,
		MaxLoopbacks:             o.MaxLoopbacks,
		DefaultHTTPStatus:        o.DefaultHTTPStatus,
		// LoadBalancer:               lbInstance,
		Timeout:                    o.TimeoutBackend,
		ResponseHeaderTimeout:      o.ResponseHeaderTimeoutBackend,
		ExpectContinueTimeout:      o.ExpectContinueTimeoutBackend,
		KeepAlive:                  o.KeepAliveBackend,
		DualStack:                  o.DualStackBackend,
		TLSHandshakeTimeout:        o.TLSHandshakeTimeoutBackend,
		MaxIdleConns:               o.MaxIdleConnsBackend,
		DisableHTTPKeepalives:      o.DisableHTTPKeepalives,
		AccessLogDisabled:          o.AccessLogDisabled,
		ClientTLS:                  o.ClientTLS,
		CustomHttpRoundTripperWrap: o.CustomHttpRoundTripperWrap,
		// RateLimiters:               ratelimitRegistry,
	}
	proxyParams.OpenTracing = &proxy.OpenTracingParams{
		Tracer:             tracer,
		InitialSpan:        o.OpenTracingInitialSpan,
		ExcludeTags:        o.OpenTracingExcludedProxyTags,
		DisableFilterSpans: o.OpenTracingDisableFilterSpans,
		LogFilterEvents:    o.OpenTracingLogFilterLifecycleEvents,
		LogStreamEvents:    o.OpenTracingLogStreamEvents,
	}

	if o.DebugListener != "" {
		do := proxyParams
		do.Flags |= proxy.Debug
		dbg := proxy.WithParams(do)
		log.Infof("debug listener on %v", o.DebugListener)
		go func() { http.ListenAndServe(o.DebugListener, dbg) /* #nosec */ }()
	}

	proxy := proxy.WithParams(proxyParams)
	defer proxy.Close()

	// wait for the first route configuration to be loaded if enabled:
	<-routing.FirstLoad()
	log.Info("Dataclients are updated once, first load complete")

	s := &Skipper{routing: routing, proxy: proxy, metricsHandler: metricsHandler}
	return s
}

func (s *Skipper) Proxy() http.Handler {
	return s.proxy
}

func (s *Skipper) Routing() http.Handler {
	return s.routing
}

func (s *Skipper) MetricsHandler() http.Handler {
	return s.metricsHandler
}

func (s *Skipper) Close() {
	s.routing.Close()
	s.proxy.Close()
}
