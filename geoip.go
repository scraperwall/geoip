package geoip

import (
	"fmt"
	"net"

	gg "github.com/oschwald/geoip2-golang"
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

// GeoIP contains metadata for an IP address from the Maxmind GeoIP databases
type GeoIP struct {
	db        *gg.Reader
	IP        net.IP    `json:"ip" bson:"ip"`
	Anonymous Anonymous `json:"anonymous" bson:"anon"`
	City      City      `json:"city" bson:"city"`
	Country   Country   `json:"country" bson:"country"`
	Domain    Domain    `json:"domain" bson:"domain"`
	ISP       ISP       `json:"isp" bson:"isp"`
}

// NewGeoIP creates a new GeoIP data structure
func NewGeoIP(dbpath string) (*GeoIP, error) {
	ggReader, err := gg.Open(dbpath)
	if err != nil {
		return nil, err
	}
	g := GeoIP{
		db: ggReader,
	}

	return &g, nil
}

// Close closes the GeoIP database
func (g *GeoIP) Close() {
	g.db.Close()
}

// Lookup performs a geo ip lookup for ipAddr in the maxmind geoip database
func (g *GeoIP) Lookup(ipAddr string) error {
	g.IP = net.ParseIP(ipAddr)
	if g.IP == nil {
		return fmt.Errorf("%s is not a valid IP address!", ipAddr)
	}

	// ANONYMOUS IP
	//
	anon, err := g.db.AnonymousIP(g.IP)
	if err == nil {
		g.Anonymous = Anonymous{
			IsAnonymous:       anon.IsAnonymous,
			IsAnonymousVPN:    anon.IsAnonymousVPN,
			IsHostingProvider: anon.IsHostingProvider,
			IsPublicProxy:     anon.IsPublicProxy,
			IsTorExitNode:     anon.IsTorExitNode,
		}
	}

	// CITY
	//
	city, err := g.db.City(g.IP)
	if err == nil {
		subdivisions := make([]string, len(city.Subdivisions), len(city.Subdivisions))
		for i, sd := range city.Subdivisions {
			subdivisions[i] = sd.Names["en"]
		}

		g.City = City{
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
	}

	// COUNTRY
	//
	country, err := g.db.Country(g.IP)
	if err == nil {
		g.Country = Country{
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
	}

	/*
		// DOMAIN
		//
		domain, err := g.db.Domain(g.IP)
		if err == nil {
			g.Domain = &Domain{
				Domain: domain.Domain,
			}
		} else {
			g.Domain = nil
		}

		// ISP
		//
		isp, err := g.db.ISP(g.IP)
		if err == nil {
			g.ISP = &ISP{
				AutonomousSystemNumber:       isp.AutonomousSystemNumber,
				AutonomousSystemOrganization: isp.AutonomousSystemOrganization,
				ISP:          isp.ISP,
				Organization: isp.Organization,
			}
		} else {
			g.ISP = nil
		}
	*/
	return nil
}
