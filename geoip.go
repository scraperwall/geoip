package geoip

import (
	"errors"
	"fmt"
	"net"

	gg "github.com/oschwald/geoip2-golang"
)

type Anonymous struct {
	// from geoip2-golang.AnonymousIP
	IsAnonymous       bool `json:"is_anonymous"`
	IsAnonymousVPN    bool `json:"is_anonymous_vpn"`
	IsHostingProvider bool `json:"is_hosting_provider"`
	IsPublicProxy     bool `json:"is_public_proxy"`
	IsTorExitNode     bool `json:"is_tor_exit_node"`
}

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

type ConnectionType struct {
	Type string `json:"connection_type"`
}

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

type Domain struct {
	Domain string `json:"domain"`
}

type ISP struct {
	AutonomousSystemNumber       uint   `json:"autonomous_system_number"`
	AutonomousSystemOrganization string `json:"autonomous_system_organization"`
	ISP                          string `json:"isp"`
	Organization                 string `json:"organization"`
}

type GeoIP struct {
	db        *gg.Reader `json:"-"`
	IP        net.IP     `json:"ip"`
	Anonymous *Anonymous `json:"anonymous"`
	City      *City      `json:"city"`
	Country   *Country   `json:"country"`
	Domain    *Domain    `json:"domain"`
	ISP       *ISP       `json:"isp"`
}

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

func (g *GeoIP) Close() {
	g.db.Close()
}

func (g *GeoIP) Lookup(ipAddr string) error {
	g.IP = net.ParseIP(ipAddr)
	if g.IP == nil {
		return errors.New(fmt.Sprintf("%s is not a valid IP address!", ipAddr))
	}

	// ANONYMOUS IP
	//
	anon, err := g.db.AnonymousIP(g.IP)
	if err == nil {
		g.Anonymous = &Anonymous{}
		g.Anonymous.IsAnonymous = anon.IsAnonymous
		g.Anonymous.IsAnonymousVPN = anon.IsAnonymousVPN
		g.Anonymous.IsHostingProvider = anon.IsHostingProvider
		g.Anonymous.IsPublicProxy = anon.IsPublicProxy
		g.Anonymous.IsTorExitNode = anon.IsTorExitNode
	} else {
		g.Anonymous = nil
	}

	// CITY
	//
	city, err := g.db.City(g.IP)
	if err == nil {
		g.City = &City{}
		g.City.AccuracyRadius = city.Location.AccuracyRadius
		g.City.Continent = city.Continent.Names["en"]
		g.City.ContinentCode = city.Continent.Code
		g.City.Country = city.Country.Names["en"]
		g.City.CountryCode = city.Country.IsoCode
		g.City.IsAnonymousProxy = city.Traits.IsAnonymousProxy
		g.City.IsSatelliteProvider = city.Traits.IsSatelliteProvider
		g.City.Latitude = city.Location.Latitude
		g.City.Longitude = city.Location.Longitude
		g.City.MetroCode = city.Location.MetroCode
		g.City.Name = city.City.Names["en"]
		g.City.Postcode = city.Postal.Code
		g.City.RegisteredCountry = city.RegisteredCountry.Names["en"]
		g.City.RegisteredCountryCode = city.RegisteredCountry.IsoCode
		g.City.RepresentedCountry = city.RepresentedCountry.Names["en"]
		g.City.RepresentedCountryCode = city.RepresentedCountry.IsoCode
		g.City.RepresentedCountryType = city.RepresentedCountry.Type

		subdivisions := make([]string, len(city.Subdivisions), len(city.Subdivisions))
		for i, sd := range city.Subdivisions {
			subdivisions[i] = sd.Names["en"]
		}
		g.City.Subdivisions = subdivisions
		g.City.Timezone = city.Location.TimeZone
	} else {
		g.City = nil
	}

	// COUNTRY
	//
	country, err := g.db.Country(g.IP)
	if err == nil {
		g.Country = &Country{}
		g.Country.Continent = country.Continent.Names["en"]
		g.Country.ContinentCode = country.Continent.Code
		g.Country.Country = country.Country.Names["en"]
		g.Country.CountryCode = country.Country.IsoCode
		g.Country.IsAnonymousProxy = country.Traits.IsAnonymousProxy
		g.Country.IsSatelliteProvider = country.Traits.IsSatelliteProvider
		g.Country.RegisteredCountry = country.RegisteredCountry.Names["en"]
		g.Country.RegisteredCountryCode = country.RegisteredCountry.IsoCode
		g.Country.RepresentedCountry = country.RepresentedCountry.Names["en"]
		g.Country.RepresentedCountryCode = country.RepresentedCountry.IsoCode
		g.Country.RepresentedCountryType = country.RepresentedCountry.Type
	} else {
		g.Country = nil
	}

	// DOMAIN
	//
	domain, err := g.db.Domain(g.IP)
	if err == nil {
		g.Domain = &Domain{}
		g.Domain.Domain = domain.Domain
	} else {
		g.Domain = nil
	}

	// ISP
	//
	isp, err := g.db.ISP(g.IP)
	if err == nil {
		g.ISP = &ISP{}
		g.ISP.AutonomousSystemNumber = isp.AutonomousSystemNumber
		g.ISP.AutonomousSystemOrganization = isp.AutonomousSystemOrganization
		g.ISP.ISP = isp.ISP
		g.ISP.Organization = isp.Organization
	} else {
		g.ISP = nil
	}

	return nil
}
