package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/tidwall/gjson"
)

type config struct {
	Filepath         string `yaml:"filepath"`
	TenantId         string `yaml:"tenantId"`
	AppId            string `yaml:"appId"`
	AppSecret        string `yaml:"appSecret"`
	ResourceAppIdUri string `yaml:"resourceAppIdUri"`
	TimeRange        string `yaml:"timerange"`
}

var appConfig config

func main() {

	configData, err := ioutil.ReadFile("config.yaml")
	handleError(err)

	err = yaml.Unmarshal(configData, &appConfig)
	handleError(err)

	err = configVerify(appConfig)
	if err != nil {
		logging(err.Error())
		panic("Check config.yaml")
	}

	token := getToken()
	alertsNjson := fetchAlerts(token)
	writeToFile(alertsNjson)

}

func configVerify(c config) error {
	if &c.AppId == nil {
		return errors.New("Error, App ID was not found ")
	} else if &c.AppSecret == nil {
		return errors.New("Error, App Secret was not found ")
	} else if &c.Filepath == nil {
		return errors.New("Error, File Path was not found ")
	} else if &c.TenantId == nil {
		return errors.New("Error, Tenant ID was not found ")
	} else if &c.TimeRange == nil {
		return errors.New("Error, Time Range was not found ")
	}
	return nil
}

func GetFilenameDate() string {

	t := time.Now()
	return "alerts-" + t.Format("2_January_2006") + ".txt"

}

func writeToFile(alerts string) {

	if alerts != "[]" {
		filename := GetFilenameDate()
		p := filepath.Join(appConfig.Filepath, filename)

		file, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		handleError(err)
		defer file.Close()

		alertsResult := gjson.Get(alerts, "value")
		alertstoWrite := ""
		alertsCount := 0

		for _, value := range alertsResult.Array() {
			alertsCount = alertsCount + 1
			alertstoWrite += value.String() + "\n"
		}
		_, err = file.WriteString(alertstoWrite)
		handleError(err)
		logging("Successful execution, found " + strconv.Itoa(alertsCount) + " new alerts")

	} else {
		logging("Successful execution, found 0 new alerts")
	}

}

func fetchAlerts(token string) string {
	token = "Bearer " + token

	layout := "2006-01-02T15:04:05.000Z"
	now := time.Now().UTC()
	duration, _ := time.ParseDuration(appConfig.TimeRange)
	timeFilter := now.Add(duration)
	// UTC time
	logging("Fetching alerts after " + timeFilter.Format(time.RFC3339Nano))
	url := "https://api.securitycenter.microsoft.com/api/alerts?$expand=evidence$filter=alertCreationTime+ge+" + timeFilter.Format(layout)

	req, err := http.NewRequest("GET", url, nil)
	handleError(err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if resp.StatusCode >= 400 && resp.StatusCode <= 499 {
		body, _ := ioutil.ReadAll(resp.Body)
		logging("Error fetching alerts: " + string(body))
	}
	handleError(err)

	alertsJson, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	fmt.Println(string(alertsJson))
	return string(alertsJson)

}

func getToken() string {

	type Response struct {
		Access_token string `json:"access_token"`
	}

	tenantId := appConfig.TenantId
	appId := appConfig.AppId
	appSecret := appConfig.AppSecret
	resourceAppIdUri := appConfig.ResourceAppIdUri
	oAuthUri := "https://login.windows.net/" + tenantId + "/oauth2/token"

	data := url.Values{
		"resource":      {resourceAppIdUri},
		"client_id":     {appId},
		"client_secret": {appSecret},
		"grant_type":    {"client_credentials"},
	}

	req, err := http.NewRequest("POST", oAuthUri, strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println(err)

	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		println(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	var result Response
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Println("Can not unmarshal JSON")
	}

	return string(result.Access_token)
}

func handleError(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func logging(logMessage string) {
	fmt.Println(logMessage)
	p := filepath.Join(appConfig.Filepath, "defender.log")
	file, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)

	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
	log.Println(logMessage)
}
