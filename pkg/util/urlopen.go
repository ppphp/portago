package util

import (
	"github.com/noaway/dateparse"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func urlopen(Url string, ifModifiedSince string) *http.Response { // false
	parseResult, _ := url.Parse(Url)
	if parseResult.Scheme != "http" && parseResult.Scheme != "https" {
		resp, _ := http.Get(Url)
		return resp
	} else {
		netloc := parseResult.Host
		u := url.URL{
			Scheme:   parseResult.Scheme,
			Host:     netloc,
			Path:     parseResult.Path,
			RawQuery: parseResult.RawQuery,
			Fragment: parseResult.Fragment,
		}
		Url = u.String()
		request, _ := http.NewRequest("GET", Url, nil)
		request.Header.Add("User-Agent", "Gentoo Portage")
		if ifModifiedSince != "" {
			request.Header.Add("If-Modified-Since", timestampToHttp(ifModifiedSince))
		}
		if parseResult.User != nil {
			pswd, _ := parseResult.User.Password()
			request.SetBasicAuth(parseResult.User.Username(), pswd)
		}
		hdl, _ := http.DefaultClient.Do(request)
		hdl.Header.Add("timestamp", httpToTimestamp(hdl.Header.Get("last-modified")))
		return hdl
	}
}

func timestampToHttp(timestamp string) string {
	ts, _ := strconv.Atoi(timestamp)
	dt := time.Unix(int64(ts), 0)
	return dt.Format("Mon Jan 02 15:04:05 -0700 2006")
}

func httpToTimestamp(httpDatetimeString string) string {
	t, _ := dateparse.ParseAny(httpDatetimeString)
	return string(t.Unix())
}
