# Microsoft-Defender-Alert-API-Integration
Microsoft Defender Alert API Integration

All alerts will be pulled based on the time framed specified in config.yaml and written into a file, one alert per line for easy parsing in SIEM.

### Integrating Micrsofot Defender with SIEM
- Compile the code using go build command 
- Fill tenantid, appid, and appsecret (api token) 
- Create scheduled tasks to run every 1 hour 
- Send the alert to the SIEM using FileBeat agent

**Configuration file**
```yaml
filepath        : C:\logs\
tenantId        : 
appId           : 
appSecret       : 
resourceAppIdUri: https://api.securitycenter.windows.com
timerange       : -1h
```

