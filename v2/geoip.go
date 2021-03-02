package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	gg "github.com/oschwald/geoip2-golang"
)

const (
	dbFile    = "GeoLite2-City.tar.gz"
	dbMd5File = "GeoLite2-City.tar.gz.md5"
)

// Anonymous contains information about whether an IP address is anonymous
type Anonymous struct {
	// from geoip2-golang.AnonymousIP
	IsAnonymous       bool `json:"is_anonymous"`
	IsAnonymousVPN    bool `json:"is_anonymous_vpn"`
	IsHostingProvider bool `json:"is_hosting_provider"`
	IsPublicProxy     bool `json:"is_public_proxy"`
	IsTorExitNode     bool `json:"is_tor_exit_node"`
}

// City contains geographic data on a city level for a given IP address
type City struct {
	Name                   string   `json:"name"`
	Continent              string   `json:"continent"`
	ContinentCode          string   `json:"continent_code"`
	Country                string   `json:"country"`
	CountryCode            string   `json:"country_code"`
	AccuracyRadius         uint16   `json:"accuracy_radius"`
	Latitude               float64  `json:"latitude"`
	Longitude              float64  `json:"longitude"`
	MetroCode              uint     `json:"metro_code"`
	Timezone               string   `json:"timezone"`
	Postcode               string   `json:"postcode"`
	RegisteredCountry      string   `json:"registered_country"`
	RegisteredCountryCode  string   `json:"registered_country_code"`
	RepresentedCountry     string   `json:"represented_country"`
	RepresentedCountryCode string   `json:"represented_country_code"`
	RepresentedCountryType string   `json:"represented_country_type"`
	Subdivisions           []string `json:"subdivisions"`
	IsAnonymousProxy       bool     `json:"is_anonymous_proxy"`
	IsSatelliteProvider    bool     `json:"is_satellite_provider"`
}

// ConnectionType denotes the connection type for a given IP address
type ConnectionType struct {
	Type string `json:"connection_type"`
}

// Country contains geographic data on a country level for a given IP address
type Country struct {
	ContinentCode          string `json:"continent_code"`
	Continent              string `json:"continent"`
	CountryCode            string `json:"country_code"`
	Country                string `json:"country"`
	RegisteredCountryCode  string `json:"registered_country_code"`
	RegisteredCountry      string `json:"registered_country"`
	RepresentedCountryCode string `json:"represented_country_code"`
	RepresentedCountryType string `json:"represented_country_type"`
	RepresentedCountry     string `json:"represented_country"`
	IsAnonymousProxy       bool   `json:"is_anonymous_proxy"`
	IsSatelliteProvider    bool   `json:"is_satellite_provider"`
}

// Domain denotes the domain for a given IP address
type Domain struct {
	Domain string `json:"domain"`
}

// ISP contains information about the autonomous system for the given IP address
type ISP struct {
	AutonomousSystemNumber       uint   `json:"autonomous_system_number"`
	AutonomousSystemOrganization string `json:"autonomous_system_organization"`
	ISP                          string `json:"isp"`
	Organization                 string `json:"organization"`
}

// DB is a geoip reader with custom methods
type DB struct {
	reader  *gg.Reader
	mutex   sync.RWMutex
	ipMutex sync.RWMutex
}

// GeoIP contains metadata for an IP address from the Maxmind GeoIP databases
type GeoIP struct {
	IP        net.IP    `json:"ip" bson:"ip"`
	Anonymous Anonymous `json:"anonymous" bson:"anon"`
	City      City      `json:"city" bson:"city"`
	Country   Country   `json:"country" bson:"country"`
	Domain    Domain    `json:"domain" bson:"domain"`
	ISP       ISP       `json:"isp" bson:"isp"`
	mutex     sync.RWMutex
	ipMutex   sync.RWMutex
}

// New creates a new GeoIP data structure
func New(baseURLOrFilename string) (*DB, error) {

	g := DB{
		mutex: sync.RWMutex{},
	}

	if strings.HasPrefix(baseURLOrFilename, "https://") || strings.HasPrefix(baseURLOrFilename, "http://") {
		err := g.fromURL(baseURLOrFilename)
		if err != nil {
			return nil, err
		}
	} else {
		fh, err := os.Open(baseURLOrFilename)
		if err != nil {
			return nil, err
		}
		err = g.fromReader(fh)
		if err != nil {
			return nil, err
		}
	}

	return &g, nil
}

func (g *DB) fromReader(reader io.Reader) error {

	// Extract the mmdb file
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	if err != nil {
		return err
	}

	for {
		header, err := tarReader.Next()

		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		// this is the mmdb database
		if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "GeoLite2-City.mmdb") {
			tmpF, err := ioutil.TempFile("/tmp", "geoip-mmdb-")
			if err != nil {
				return err
			}

			_, err = io.Copy(tmpF, tarReader)
			if err != nil {
				return err
			}

			tmpF.Close()

			defer os.Remove(tmpF.Name())

			ggReader, err := gg.Open(tmpF.Name())
			if err != nil {
				return err
			}

			g.mutex.Lock()
			defer g.mutex.Unlock()

			if g.reader != nil {
				g.reader.Close()
			}
			g.reader = ggReader

			return nil
		}
	}

	return nil
}

// Load loads the GeoIP City Database from Maxmind
func (g *DB) fromURL(baseURL string) error {

	// Get MD5 sum for tar.gz file
	dbMd5URL := baseURL + "/" + dbMd5File
	resp, err := http.Get(dbMd5URL)
	if err != nil {
		return err
	}

	md5Sum, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Load the tar.gz file
	dbURL := baseURL + "/" + dbFile
	resp, err = http.Get(dbURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Build the MD5 sum of the downloaded tar.gz
	hash := md5.New()
	if _, err := io.Copy(hash, bytes.NewReader(bodyData)); err != nil {
		return err
	}
	if string(md5Sum) != hex.EncodeToString(hash.Sum(nil)) {
		return fmt.Errorf("checksum mismatch: %s != %s", md5Sum, hash.Sum(nil))
	}

	return g.fromReader(bytes.NewReader(bodyData))
}

// Close closes the GeoIP database
func (g *DB) Close() {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.reader.Close()
}

// Lookup looks up the geo ip data for the given IP address
func (g *DB) Lookup(ip net.IP) (*GeoIP, error) {
	if ip == nil {
		return nil, fmt.Errorf("ip is nil")
	}

	g.mutex.Lock()
	defer g.mutex.Unlock()

	res := &GeoIP{
		IP: ip,
	}

	// ANONYMOUS IP
	//
	anon, err := g.reader.AnonymousIP(ip)
	if err == nil {
		res.Anonymous = Anonymous{
			IsAnonymous:       anon.IsAnonymous,
			IsAnonymousVPN:    anon.IsAnonymousVPN,
			IsHostingProvider: anon.IsHostingProvider,
			IsPublicProxy:     anon.IsPublicProxy,
			IsTorExitNode:     anon.IsTorExitNode,
		}
	}

	// CITY
	//
	city, err := g.reader.City(ip)
	if err == nil {
		subdivisions := make([]string, len(city.Subdivisions), len(city.Subdivisions))
		for i, sd := range city.Subdivisions {
			subdivisions[i] = sd.Names["en"]
		}

		res.City = City{
			AccuracyRadius:         city.Location.AccuracyRadius,
			Continent:              city.Continent.Names["en"],
			ContinentCode:          city.Continent.Code,
			Country:                city.Country.Names["en"],
			CountryCode:            city.Country.IsoCode,
			IsAnonymousProxy:       city.Traits.IsAnonymousProxy,
			IsSatelliteProvider:    city.Traits.IsSatelliteProvider,
			Latitude:               city.Location.Latitude,
			Longitude:              city.Location.Longitude,
			MetroCode:              city.Location.MetroCode,
			Name:                   city.City.Names["en"],
			Postcode:               city.Postal.Code,
			RegisteredCountry:      city.RegisteredCountry.Names["en"],
			RegisteredCountryCode:  city.RegisteredCountry.IsoCode,
			RepresentedCountry:     city.RepresentedCountry.Names["en"],
			RepresentedCountryCode: city.RepresentedCountry.IsoCode,
			RepresentedCountryType: city.RepresentedCountry.Type,
			Subdivisions:           subdivisions,
			Timezone:               city.Location.TimeZone,
		}
	} else {
		return nil, fmt.Errorf("failed to load city data for %s", ip)
	}

	// COUNTRY
	//
	country, err := g.reader.Country(ip)
	if err == nil {
		res.Country = Country{
			Continent:              country.Continent.Names["en"],
			ContinentCode:          country.Continent.Code,
			Country:                country.Country.Names["en"],
			CountryCode:            country.Country.IsoCode,
			IsAnonymousProxy:       country.Traits.IsAnonymousProxy,
			IsSatelliteProvider:    country.Traits.IsSatelliteProvider,
			RegisteredCountry:      country.RegisteredCountry.Names["en"],
			RegisteredCountryCode:  country.RegisteredCountry.IsoCode,
			RepresentedCountry:     country.RepresentedCountry.Names["en"],
			RepresentedCountryCode: country.RepresentedCountry.IsoCode,
			RepresentedCountryType: country.RepresentedCountry.Type,
		}
	} else {
		return nil, fmt.Errorf("failed to load country data for %s", ip)
	}

	return res, nil
}
