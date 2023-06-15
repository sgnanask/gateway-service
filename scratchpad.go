package main

// package main

// import (
// 	"bytes"
// 	"fmt"
// 	"log"
// 	"os"
// 	"runtime"
// 	"strconv"
// )

// func main() {
// 	log.Println("Go routine id", getGID())
// 	log.Printf("Initial GOMAXPROCS - %d\n", runtime.GOMAXPROCS(0))
// 	log.Printf("Num of cpus - %d\n", runtime.NumCPU())
// 	log.Printf("Initial GOMAXPROCS - %d\n", runtime.GOMAXPROCS(-1))

// 	fmt.Println("Hello World")
// 	fmt.Println("Program arguments", os.Args)
// 	fmt.Println("Called heapAnalysis", heapAnalysis())

// }

// func getGID() uint64 {
// 	b := make([]byte, 64)
// 	b = b[:runtime.Stack(b, false)]
// 	b = bytes.TrimPrefix(b, []byte("goroutine "))
// 	b = b[:bytes.IndexByte(b, ' ')]
// 	n, _ := strconv.ParseUint(string(b), 10, 64)
// 	return n
// }

// // heapAnalysis returns *int pointer
// //
// //go:noinline
// func heapAnalysis() *int {
// 	data := 55
// 	return &data
// }

// Reverse proxy
// router.POST("/api/v1/endpoint1", ReverseProxy()

// func ReverseProxy(target string) gin.HandlerFunc {
//     url, err := url.Parse(target)
//     checkErr(err)
//     proxy := httputil.NewSingleHostReverseProxy(url)
//     return func(c *gin.Context) {
//         proxy.ServeHTTP(c.Writer, c.Request)
//     }
// }
//
// func ReverseProxy() gin.HandlerFunc {
//
//     target := "localhost:3000"
//
//     return func(c *gin.Context) {
//         director := func(req *http.Request) {
//             r := c.Request
//             req = r
//             req.URL.Scheme = "http"
//             req.URL.Host = target
//             req.Header["my-header"] = []string{r.Header.Get("my-header")}
//                         // Golang camelcases headers
//             delete(req.Header, "My-Header")
//         }
//         proxy := &httputil.ReverseProxy{Director: director}
//         proxy.ServeHTTP(c.Writer, c.Request)
//     }
// }
// func proxy(c *gin.Context) {
// 	remote, err := url.Parse("http://myremotedomain.com")
// 	if err != nil {
// 		panic(err)
// 	}

// 	proxy := httputil.NewSingleHostReverseProxy(remote)
// 	//Define the director func
// 	//This is a good place to log, for example
// 	proxy.Director = func(req *http.Request) {
// 		req.Header = c.Request.Header
// 		req.Host = remote.Host
// 		req.URL.Scheme = remote.Scheme
// 		req.URL.Host = remote.Host
// 		req.URL.Path = c.Param("proxyPath")
// 	}

// 	proxy.ServeHTTP(c.Writer, c.Request)
// }
//
// g, _ := ginproxy.NewGinProxy("http://backend01.example.com/")
// router.Any("/api/*all", g.Handler)
