package main

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"gateway-service/log"
	"gateway-service/middleware"
	"gateway-service/middleware/skipper"

	zskipper "github.com/zalando/skipper"

	"net/http"
	_ "net/http/pprof"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/location"

	"golang.org/x/sync/errgroup"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

func handler1(c *gin.Context) {

	log.Info("handler 1 - before processing")

	c.Next()

	log.Info("handler 1 - after processing")

}

func handler2(c *gin.Context) {

	log.Info("handler 2 - before processing")

	c.Next()

	log.Info("handler 2 - after processing")
}

func loggerMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(params gin.LogFormatterParams) string {
		return fmt.Sprintf("%s - [%s] \"%s %s %s\" %d %s %d \"%s\" %s\n",
			params.ClientIP,
			params.TimeStamp.Format(time.RFC1123),
			params.Method,
			params.Path,
			params.Request.Proto,
			params.StatusCode,
			params.Latency,
			params.BodySize,
			params.Request.UserAgent(),
			// Is this really needed?
			params.ErrorMessage,
		)
	},
	)
}

type KV map[string]interface{}

func isType(a, b interface{}) bool {
	return reflect.TypeOf(a) == reflect.TypeOf(b)
}

func main() {
	log.Info("Initializing skipper")
	s := "testing"
	log.Infof("Formatting a string %s", s)
	log.Infow("This is a message", map[string]interface{}{
		"bar": "baz",
		"n":   1,
	})

	options := skipper.Options{zskipper.Options{
		RoutesFile:          "routes.eskip",
		IgnoreTrailingSlash: true,
		WaitFirstRouteLoad:  true,

		MetricsFlavours: []string{"codahale", "prometheus"},
		// MetricsPrefix:   "skipper.",

		DebugListener: ":9280",

		EnableProfile:        false,
		EnableDebugGcMetrics: true,
		EnableRuntimeMetrics: true,

		EnableServeRouteMetrics:       true,
		EnableServeRouteCounter:       true,
		EnableServeHostMetrics:        true,
		EnableServeHostCounter:        true,
		EnableServeMethodMetric:       true,
		EnableServeStatusCodeMetric:   true,
		EnableBackendHostMetrics:      true,
		EnableCombinedResponseMetrics: true,

		EnableAllFiltersMetrics:             true,
		EnableRouteResponseMetrics:          true,
		EnableRouteBackendErrorsCounters:    true,
		EnableRouteStreamingErrorsCounters:  true,
		EnableRouteBackendMetrics:           true,
		DisableMetricsCompatibilityDefaults: false,

		OAuthTokeninfoURL: "http://localhost:54321/auth/v1/user",
	},
	}
	skipper := skipper.New(options)
	defer skipper.Close()

	log.Info("Done initializing skipper")

	router := gin.New()
	router.Use(loggerMiddleware())
	router.Use(gin.Recovery())

	router.Use(gin.WrapH(skipper.Proxy()))
	router.Use(middleware.Timeout())
	router.Use(gzip.Gzip(gzip.DefaultCompression))

	addServiceHandlers(router)

	server := &http.Server{
		Addr:         ":9180",
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	managementRouter := gin.New()
	managementRouter.Use(loggerMiddleware(), gin.Recovery())

	// We can add authentication for /admin if needed
	adminGroup := managementRouter.Group("/admin")

	// Pprof
	pprof.RouteRegister(adminGroup, "pprof")

	// Routes
	adminGroup.GET("/routes", gin.WrapH(skipper.Routing()))

	// Metrics
	handler := skipper.MetricsHandler()
	managementRouter.GET("/metrics", gin.WrapH(handler))

	managementServer := &http.Server{
		Addr:    ":9181",
		Handler: managementRouter,
	}

	// Http Client Timeout
	// c := &http.Client{
	// 	Timeout: 5 * time.Second,
	// }
	// resp, err := c.Get("https://blog.filippo.io/")

	var g errgroup.Group

	g.Go(func() error {
		return server.ListenAndServe()
	})

	g.Go(func() error {
		return managementServer.ListenAndServe()
	})

	if err := g.Wait(); err != nil {
		log.Fatal(err)
	}
}

func addServiceHandlers(router *gin.Engine) {

	router.GET("/health", middleware.Health())

	router.GET("/some/other/path", handlePing)

	v1Group := router.Group("/v1")
	v1Group.GET("/ping", handlePing)
	v1Group.GET("/delayed-ping", handleDelayedPing)
}

func handlePing(c *gin.Context) {
	url := location.Get(c)
	log.Printf("location %v\n", url)
	c.JSON(200, gin.H{"message": "pong"})
}

func handleDelayedPing(c *gin.Context) {
	st := c.Query("time")
	if st != "" {
		t, _ := strconv.Atoi(st)
		d := time.Duration(t) * time.Second
		log.Println("Sleeping for", d)
		time.Sleep(d)

	}
	c.JSON(200, gin.H{"message": "pong"})
}
