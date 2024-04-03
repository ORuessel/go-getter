package getter

import (
    "fmt"
    "net/url"
    "strings"
)

// S3Detector implements Detector to detect S3 URLs and turn
// them into URLs that the S3 getter can understand.
type S3Detector struct{}

func (d *S3Detector) Detect(src, _ string) (string, bool, error) {
    if len(src) == 0 {
        return "", false, nil
    }

    if strings.Contains(src, ".amazonaws.com/") {
        return d.detectHTTP(src)
    }

    return "", false, nil
}

func (d *S3Detector) detectHTTP(src string) (string, bool, error) {
    parts := strings.Split(src, "/")
    if len(parts) < 2 {
        return "", false, fmt.Errorf("URL is not a valid S3 URL")
    }

    hostParts := strings.Split(parts[0], ".")
    switch {
    case len(hostParts) == 3:
        return d.detectPathStyle(hostParts[0], parts[1:])
    case len(hostParts) == 4:
        return d.detectVhostStyle(hostParts[1], hostParts[0], parts[1:])
    case len(hostParts) == 5 && hostParts[1] == "s3":
        return d.detectNewVhostStyle(hostParts[2], hostParts[0], parts[1:])
    case len(hostParts) > 5 && strings.Contains(hostParts[1], "vpce"): // New case for VPC endpoint URLs
        return d.detectVPCEStyle(hostParts, parts[1:])
    default:
        return "", false, fmt.Errorf("URL is not a valid S3 URL")
    }
}

func (d *S3Detector) detectPathStyle(region string, parts []string) (string, bool, error) {
    urlStr := fmt.Sprintf("https://%s.amazonaws.com/%s", region, strings.Join(parts, "/"))
    url, err := url.Parse(urlStr)
    if err != nil {
        return "", false, fmt.Errorf("error parsing S3 URL: %s", err)
    }

    return "s3::" + url.String(), true, nil
}

func (d *S3Detector) detectVhostStyle(region, bucket string, parts []string) (string, bool, error) {
    urlStr := fmt.Sprintf("https://%s.amazonaws.com/%s/%s", region, bucket, strings.Join(parts, "/"))
    url, err := url.Parse(urlStr)
    if err != nil {
        return "", false, fmt.Errorf("error parsing S3 URL: %s", err)
    }

    return "s3::" + url.String(), true, nil
}

func (d *S3Detector) detectNewVhostStyle(region, bucket string, parts []string) (string, bool, error) {
    urlStr := fmt.Sprintf("https://s3.%s.amazonaws.com/%s/%s", region, bucket, strings.Join(parts, "/"))
    url, err := url.Parse(urlStr)
    if err != nil {
        return "", false, fmt.Errorf("error parsing S3 URL: %s", err)
    }

    return "s3::" + url.String(), true, nil
}

// New function to handle the special VPC endpoint style URLs.
func (d *S3Detector) detectVPCEStyle(hostParts []string, parts []string) (string, bool, error) {
    // Assuming the bucket name is the first part and the region is the fourth part
    bucket := hostParts[0]
    region := hostParts[3]
    urlStr := fmt.Sprintf("https://s3.%s.amazonaws.com/%s/%s", region, bucket, strings.Join(parts, "/"))
    url, err := url.Parse(urlStr)
    if err != nil {
        return "", false, fmt.Errorf("error parsing S3 URL: %s", err)
    }

    return "s3::" + url.String(), true, nil
}
