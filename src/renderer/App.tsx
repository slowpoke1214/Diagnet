import {MemoryRouter as Router, Route, Routes} from 'react-router-dom';
import './App.css';

import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListSubheader from '@mui/material/ListSubheader';
import Paper from '@mui/material/Paper';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import Toolbar from '@mui/material/Toolbar';
import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Stepper from '@mui/material/Stepper';
import Step from '@mui/material/Step';
import StepLabel from '@mui/material/StepLabel';
import StepContent from '@mui/material/StepContent';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Chart from 'chart.js/auto'
import {CategoryScale} from "chart.js";
import {Pie} from "react-chartjs-2";

import LoadingButton from '@mui/lab/LoadingButton';

import SensorsIcon from '@mui/icons-material/Sensors';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import NumbersIcon from '@mui/icons-material/Numbers';
import ManageHistoryIcon from '@mui/icons-material/ManageHistory';
import InfoIcon from '@mui/icons-material/Info';
import DescriptionIcon from '@mui/icons-material/Description';
import {useState} from "react";

Chart.register(CategoryScale);

function Main() {
    const [scanResultsArray, setScanResultsArray] = useState([]);
    const [loadingBool, setLoading] = useState(false);

    return (
        // ----------Navbar----------
      <div>
          <Box sx={{ flexGrow: 1 }}>
              <AppBar position="static">
                  <Toolbar variant="dense">
                      <Typography variant="h5" color="inherit" component="div" className={"mainPageHeader"}>
                          Diagnet
                      </Typography>
                  </Toolbar>
              </AppBar>
          </Box>

          {/* ----------Information / Start Scan Button---------- */}

          <div className={'upperInformationSection'}>
              <Typography className={'information'}>
                  Diagnet is a lightweight and easy to use network scanner, capable of
                  determining online hosts, service and operating system information, and
                  relevant Common Vulnerabilities and Exposures (CVE's) associated with discovered services.
                  To begin scanning, press the button below.

                  <br/> <br/>
                  <b>This product uses data from the NVD API but is not endorsed or certified by the NVD</b>
              </Typography>
              <div className={'scanButton'}>
                  <LoadingButton
                      loading={loadingBool}
                      loadingPosition="start"
                      startIcon={<SensorsIcon/>}
                      variant="outlined"
                      onClick={() => {
                          try {
                              setLoading(true);
                              scanner(scanResultsArray, setScanResultsArray, setLoading).then(r => {
                              });
                          } catch (e) {
                              console.log(e)
                          }
                      }}
                  >
                      <span>{loadingBool ? 'Scanning' : 'Start Scan'}</span>
                  </LoadingButton>
              </div>
          </div>

          {/* ----------Main Content---------- */}

          <div className={'papersColumn'}>
              {scanResultsArray.reverse().map((scanResult, index) => (
                  <div key={index} className={'papers'}>
                      {scanResult}
                  </div>
              ))}
          </div>

      </div>
  );
}

async function scanner(scanResultsArray: any, setScanResultsArray: any, setLoading: any) {
    // This function Should asynchronously handle receiving every step

    // Get current date and time
    const currDate = new Date().toLocaleDateString();
    const currTime = new Date().toLocaleTimeString();
    const startTime = new Date();

    const steps = [
        {
            label: 'Scanning ports on discovered machines for active services',
            description:
                'This scan iterates through each discovered host, and checks ports 1-1024 for active services.',
        },
        {
            label: 'Use NIST National Vulnerability Database (NVD) API for known vulnerabilities',
            description: `Using the publicly available NIST NVD API with discovered service information. This step takes approximately 6 seconds / CPE.`,
        },
        {
            label: 'Network Recommendation',
            description: `Network recommendations have been generated at the bottom.`,
        },
    ];

    const startingResult = (
        <Paper elevation={3}>
            <div className={'paperTitle'}>
                <Typography>
                    <b>Scan Type: </b>Network Scan <br/>
                    <b>Date/Time: </b>{currDate} - {currTime} <br/>
                    <br/>
                </Typography>
            </div>

            <div className={'primaryContent'}>
                <div className={'scanStepper'}>
                    <Stepper activeStep={0} orientation="vertical">
                        {steps.map((step, index) => (
                            <Step key={step.label}>
                                <StepLabel
                                    optional={
                                        index === 2 ? (
                                            <Typography variant="caption">Last step</Typography>
                                        ) : null
                                    }
                                >
                                    {step.label}
                                </StepLabel>
                                <StepContent>
                                    <Typography>{step.description}</Typography>
                                </StepContent>
                            </Step>
                        ))}
                    </Stepper>
                </div>
            </div>
        </Paper>
    );

    await updateScanResult(scanResultsArray, setScanResultsArray, startingResult);

    /*
        ---------DEVICE SCAN---------
    */
    // Run device scan
    const devices = await window.electron.ipcRenderer.scanDevices();

    // Check if IP could be identified
    if (devices == 'ipNotFound') {
        setLoading(false);  // Reset the buttons status

        // Clear the DOM
        await updateScanResult(
            scanResultsArray,
            setScanResultsArray,
            '');

        // Alert the user of the error
        alert('The local IP address could not be identified, ' +
            'ensure you are connected to the internet.');
        return
    }

    console.log('---- Devices From IPC ----', devices);

    const deviceScanResult = (
        <Paper elevation={3}>
            <div className={'paperTitle'}>
                <Typography>
                    <b>Scan Type: </b>Network Scan <br/>
                    <b>Date/Time: </b>{currDate} - {currTime} <br/>
                    <b>Detected Devices: </b> {devices.length} <br/>
                    <br/>
                </Typography>
            </div>

            <div className={'primaryContent'}>
                <div className={'scanStepper'}>
                    <Stepper activeStep={0} orientation="vertical">
                        {steps.map((step, index) => (
                            <Step key={step.label}>
                                <StepLabel
                                    optional={
                                        index === 2 ? (
                                            <Typography variant="caption">Last step</Typography>
                                        ) : null
                                    }
                                >
                                    {step.label}
                                </StepLabel>
                                <StepContent>
                                    <Typography>{step.description}</Typography>
                                </StepContent>
                            </Step>
                        ))}
                    </Stepper>
                </div>

                <div className={'scanContent'}>
                    {devices.map((item: any, index: any) => (
                        <Accordion key={index} elevation={3}>
                            <AccordionSummary
                                expandIcon={<ExpandMoreIcon/>}
                                aria-controls={`panel${index}-content`}
                                id={`panel${index}-header`}
                            >
                                <Typography>{item}</Typography>
                            </AccordionSummary>
                            <AccordionDetails>
                                <Typography>{item.content}</Typography>
                            </AccordionDetails>
                        </Accordion>
                    ))}
                </div>
            </div>
        </Paper>
    );

    await updateScanResult(scanResultsArray, setScanResultsArray, deviceScanResult);

    /*
        ---------OS and PORT SCAN---------
    */
    let servicesResult: any[] = [];  // Define services result array
    try {
        servicesResult = JSON.parse(await window.electron.ipcRenderer.scanPorts(devices));
        // servicesResult = []
        // servicesResult = [{
        //     "192.168.1.13": {
        //         "os": ["Linux 4.15 - 5.6"],
        //         "ports": [{
        //             "OpenSSH": {
        //                 "CPE": "cpe:/a:openbsd:openssh:8.2p1",
        //                 "port": "22",
        //                 "version": "8.2p1 Ubuntu 4ubuntu0.5"
        //             }
        //         }, {
        //             "nginx": {
        //                 "CPE": "cpe:/a:igor_sysoev:nginx:1.18.0",
        //                 "port": "80",
        //                 "version": "1.18.0"
        //             }
        //         }, {
        //             "snort": {
        //                 "CPE": "cpe:/a:openbsd:openssh:4.1:p1",
        //                 "port": "193",
        //                 "version": "4.1"
        //             }
        //         }
        //         ]
        //     }, "192.168.1.69": {
        //         "os": ["Linux 1.15 - 5.6"],
        //         "ports": [{
        //             "OpenSSH": {
        //                 "CPE": "cpe:/a:openbsd:openssh:8.2p1",
        //                 "port": "69",
        //                 "version": "8.2p1 Ubuntu 4ubuntu0.5"
        //             }
        //         }, {
        //             "nginx": {
        //                 "CPE": "cpe:/a:igor_sysoev:nginx:1.18.0",
        //                 "port": "80",
        //                 "version": "1.18.0"
        //             }
        //         }, {
        //             "apache": {
        //                 "CPE": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
        //                 "port": "96",
        //                 "version": "1.3"
        //             }
        //         }, {
        //             "windows": {
        //                 "CPE": "cpe:/o:microsoft:windows",
        //                 "port": "12",
        //                 "version": "7"
        //             }
        //         }
        //         ]
        //     }, "192.168.1.104": {
        //         "ports": [{
        //                 "Dropbear sshd": {
        //                     "CPE": null,
        //                     "version": null,
        //                     "port": "22"
        //                 }
        //             }, {
        //             "Apache": {
        //                 "CPE": "cpe:/a:openbsd:openssh:7.3:p1",
        //                 "version": "7.3",
        //                 "port": "88"
        //             }}
        //         ],
        //         "os": [
        //             "OpenWrt Chaos Calmer 15.05 (Linux 3.18) or Designated Driver (Linux 4.1 or 4.4)"
        //         ]
        //     }
        // }]

    } catch (e) {
        console.log('Error in scanning ports: ' + e);
    }
    // setLoading(false);
    console.log('---- Services Result from IPC ----', servicesResult);

    const portScanResult = (
        <Paper elevation={5}>
            <div className={'paperTitle'}>
                <Typography>
                    <b>Scan Type: </b>Network Scan <br/>
                    <b>Date/Time: </b>{currDate} - {currTime} <br/>
                    <b>Detected Devices: </b> {devices.length} <br/>
                    <br/>
                </Typography>
            </div>

            <div className={'primaryContent'}>
                <div className={'scanStepper'}>
                    <Stepper activeStep={1} orientation="vertical">
                        {steps.map((step, index) => (
                            <Step key={step.label}>
                                <StepLabel
                                    optional={
                                        index === 2 ? (
                                            <Typography variant="caption">Last step</Typography>
                                        ) : null
                                    }
                                >
                                    {step.label}
                                </StepLabel>
                                <StepContent>
                                    <Typography>{step.description}</Typography>
                                </StepContent>
                            </Step>
                        ))}
                    </Stepper>
                </div>

                <div className={'scanContent'}>
                    {devices.map((item: any, index: any) => {
                        // Check for a match
                        const matchingItem: any = servicesResult.find((result) => result[item]);
                        const ports = matchingItem ? matchingItem[item].ports : [];
                        const os = matchingItem?.[item]?.os?.[0] ?? 'N/A'; // Nullish Coalescing operator to ensure value is not null or undefined

                        return (
                            <Accordion key={index}>
                                <AccordionSummary
                                    expandIcon={<ExpandMoreIcon/>}
                                    aria-controls={`panel${index}-content`}
                                    id={`panel${index}-header`}
                                >
                                    <Typography variant={"h6"}>{item}</Typography>
                                </AccordionSummary>
                                <AccordionDetails>
                                    <div>
                                        <Stack direction="row" spacing={1} className={'serviceResultContentOS'}>
                                            <Chip icon={<ManageHistoryIcon />} label="OS" variant="outlined" />
                                            <Typography className={'serviceResultContentTypography'}>{os || '-'}</Typography>
                                        </Stack>
                                    </div>
                                    <div>
                                        {ports.map((portItem: any, portIndex: number) => {
                                            const portName = Object.keys(portItem)[0];
                                            const portData = portItem[portName];
                                            return (
                                                <Paper elevation={6} className={'serviceResultsPaper'} key={portIndex}>
                                                    <div className={'serviceResultsContent'}>
                                                        <Stack direction="row" spacing={1} className={'serviceResultContentPortname'}>
                                                            <Chip icon={<InfoIcon />} label="Service Name" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portName}</Typography>
                                                        </Stack>
                                                        <Stack direction="row" spacing={2} className={'serviceResultContentCPE'}>
                                                            <Chip icon={<HelpOutlineIcon />} label="CPE" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portData.CPE || '-'}</Typography>
                                                        </Stack>
                                                        <Stack direction="row" spacing={3} className={'serviceResultContentPort'}>
                                                            <Chip icon={<NumbersIcon />} label="Port" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portData.port || '-'}</Typography>
                                                        </Stack>
                                                        <Stack direction="row" spacing={1} className={'serviceResultContentVersion'}>
                                                            <Chip icon={<ManageHistoryIcon />} label="Version" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portData.version || '-'}</Typography>
                                                        </Stack>
                                                    </div>
                                                </Paper>
                                            );
                                        })}
                                    </div>
                                </AccordionDetails>
                            </Accordion>
                        );
                    })}
                </div>
            </div>
        </Paper>
    );

    await updateScanResult(scanResultsArray, setScanResultsArray, portScanResult);

    /*
        ---------NIST NVD API---------
    */

    let CVEInfo = await callCVE(JSON.stringify(servicesResult));
    // let CVEInfo = await window.electron.ipcRenderer.scanCVE(JSON.stringify(servicesResult));
    CVEInfo = JSON.parse(CVEInfo);
    console.log('---- CVE Results from IPC ---- ',CVEInfo);
    const randomNum = () => Math.floor(Math.random() * (235 - 52 + 1) + 52);
    const randomRGB = () => `rgb(${randomNum()}, ${randomNum()}, ${randomNum()})`;

    // Time Management
    const endTime = new Date();
    const timeDiff = endTime.getTime() - startTime.getTime();
    // Convert time difference to seconds, minutes, and hours
    const seconds = Math.floor(timeDiff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    var ipChartArr: { ip: any; totalCve: number; }[] = [];

    const cveScanResult = (
        <Paper elevation={6}>
            <div className={'paperTitle'}>
                <Typography>
                    <b>Scan Type: </b>Network Scan <br/>
                    <b>Date/Time: </b>{currDate} - {currTime} <br/>
                    <b>Detected Devices: </b> {devices.length} <br/>
                    <b>Scan Time: </b> {`Scan time: ${hours} hours, ${minutes % 60} minutes, ${seconds % 60} seconds`} <br/>
                    <br/>
                </Typography>
            </div>

            <div className={'primaryContent'}>
                <div className={'scanStepper'}>
                    <Stepper activeStep={2} orientation="vertical">
                        {steps.map((step, index) => (
                            <Step key={step.label}>
                                <StepLabel
                                    optional={
                                        index === 2 ? (
                                            <Typography variant="caption">Last step</Typography>
                                        ) : null
                                    }
                                >
                                    {step.label}
                                </StepLabel>
                                <StepContent>
                                    <Typography>{step.description}</Typography>
                                </StepContent>
                            </Step>
                        ))}
                    </Stepper>
                </div>

                <div className={'scanContent'}>
                    {devices.map((item: any, index: any) => {
                        // Check for a match
                        const matchingItem: any = servicesResult.find((result) => result[item]);
                        const ports = matchingItem ? matchingItem[item].ports : [];

                        // Nullish Coalescing operator to ensure value is not null or undefined
                        const os = matchingItem?.[item]?.os?.[0] ?? 'N/A';

                        const randomNum = () => Math.floor(Math.random() * (235 - 52 + 1) + 52);
                        const randomRGB = () => `rgb(${randomNum()}, ${randomNum()}, ${randomNum()})`;

                        var serviceChartArr: { serviceName: any; totalResults: any; }[] = [];
                        let pieServiceVulnsData = {};

                        ipChartArr.push({
                            "ip": item,
                            "totalCve": 0
                        })

                        return (
                            <Accordion key={index} elevation={6}>
                                <AccordionSummary
                                    expandIcon={<ExpandMoreIcon/>}
                                    aria-controls={`panel${index}-content`}
                                    id={`panel${index}-header`}
                                >
                                    <Typography variant={"h6"}>{item}</Typography>
                                </AccordionSummary>
                                <AccordionDetails>
                                    <div>
                                        <Stack direction="row" spacing={1} className={'serviceResultContentOS'}>
                                            <Chip icon={<ManageHistoryIcon />} label="OS" variant="outlined" />
                                            <Typography className={'serviceResultContentTypography'}>{os || '-'}</Typography>
                                        </Stack>
                                    </div>
                                    <div>
                                        {ports.map((portItem: any, portIndex: number) => {
                                            const portName = Object.keys(portItem)[0];
                                            const portData = portItem[portName];
                                            return (
                                                <Paper elevation={6} className={'serviceResultsPaper'} key={portIndex}>
                                                    <div className={'serviceResultsContent'}>
                                                        <Stack direction="row" spacing={1} className={'serviceResultContentPortname'}>
                                                            <Chip icon={<InfoIcon />} label="Service Name" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portName}</Typography>
                                                        </Stack>
                                                        <Stack direction="row" spacing={2} className={'serviceResultContentCPE'}>
                                                            <Chip icon={<HelpOutlineIcon />} label="CPE" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portData.CPE || '-'}</Typography>
                                                        </Stack>
                                                        <Stack direction="row" spacing={3} className={'serviceResultContentPort'}>
                                                            <Chip icon={<NumbersIcon />} label="Port" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portData.port || '-'}</Typography>
                                                        </Stack>
                                                        <Stack direction="row" spacing={1} className={'serviceResultContentVersion'}>
                                                            <Chip icon={<ManageHistoryIcon />} label="Version" variant="outlined" />
                                                            <Typography className={'serviceResultContentTypography'}>{portData.version || '-'}</Typography>
                                                        </Stack>
                                                        <Accordion key={index} elevation={5}>
                                                            <AccordionSummary
                                                                expandIcon={<ExpandMoreIcon/>}
                                                                aria-controls={`panel${index}-content`}
                                                                id={`panel${index}-header`}
                                                            >
                                                                <Typography variant={"h6"}>CVE Results</Typography>
                                                            </AccordionSummary>
                                                            <AccordionDetails>
                                                                <List
                                                                    sx={{
                                                                        width: '100%',
                                                                        maxWidth: 500,
                                                                        bgcolor: 'background.paper',
                                                                        position: 'relative',
                                                                        overflow: 'auto',
                                                                        maxHeight: 300,
                                                                        '& ul': { padding: 0 },
                                                                    }}
                                                                >
                                                                    {CVEInfo.map((cveItem: any, cveIndex: number) => {
                                                                        for (const service of cveItem.cveResults) {
                                                                            if (item == cveItem.address) {
                                                                                if (service.serviceName == portName) {
                                                                                    // Service is the same, display all CVE information collected

                                                                                    const cveTotalResults = service.cveTotalResults;

                                                                                    if (cveTotalResults > 0) {
                                                                                        serviceChartArr.push({
                                                                                            "serviceName": service.serviceName,
                                                                                            "totalResults": cveTotalResults
                                                                                        })
                                                                                    }

                                                                                    // Locate the index for the ipChartArr with the matching IP Address
                                                                                    const ipChartArrIndex = ipChartArr.findIndex(i => i.ip === item);
                                                                                    if (ipChartArrIndex !== -1) {
                                                                                        // Check the index exists
                                                                                        if (service.cveTotalResults > 0) {
                                                                                            // Check the service has a value for total CVE
                                                                                            // Increment the IP addresses associated cve values
                                                                                            ipChartArr[ipChartArrIndex].totalCve += parseInt(cveTotalResults);
                                                                                        }
                                                                                    }

                                                                                    return (
                                                                                        <div
                                                                                            className={'cveResultDiv'}
                                                                                            key={cveIndex}>
                                                                                            <Stack direction="row" spacing={3} className={'cveResults'}>
                                                                                                <Chip icon={<NumbersIcon/>} label="Number of CVEs" variant="outlined"/>
                                                                                                <Typography
                                                                                                    className={'serviceResultContentTypography'}>{cveTotalResults || '0'}
                                                                                                </Typography>
                                                                                            </Stack>
                                                                                            {service.cveData.map((cve: any, cveIndex: number) => (
                                                                                                <ListItem
                                                                                                    key={cveIndex}>
                                                                                                    <Accordion
                                                                                                        key={cveIndex}>
                                                                                                        <AccordionSummary
                                                                                                            expandIcon={
                                                                                                                <ExpandMoreIcon/>}
                                                                                                            aria-controls={`panel${index}-content`}
                                                                                                            id={`panel${index}-header`}
                                                                                                        >
                                                                                                            <Typography>
                                                                                                                <b>CVE ID: </b>
                                                                                                                {cve.cveID}
                                                                                                            </Typography>
                                                                                                        </AccordionSummary>
                                                                                                        <AccordionDetails>
                                                                                                            <Stack direction="row" spacing={3} className={'cveResultScore'}>
                                                                                                                <Chip
                                                                                                                    icon={<NumbersIcon/>}
                                                                                                                    label="Base Score"
                                                                                                                    variant="outlined"
                                                                                                                    style={{
                                                                                                                        backgroundColor:
                                                                                                                        parseFloat(cve.cveBaseScore) >= 0.0 && parseFloat(cve.cveBaseScore) < 4
                                                                                                                            ? 'green'
                                                                                                                            : parseFloat(cve.cveBaseScore) >= 4 && parseFloat(cve.cveBaseScore) < 7
                                                                                                                            ? 'yellow'
                                                                                                                            : parseFloat(cve.cveBaseScore) >= 7 && parseFloat(cve.cveBaseScore) < 9
                                                                                                                            ? 'red'
                                                                                                                            : parseFloat(cve.cveBaseScore) >= 9 && parseFloat(cve.cveBaseScore) <= 10
                                                                                                                            ? 'black'
                                                                                                                            : '',
                                                                                                                        color:
                                                                                                                        parseFloat(cve.cveBaseScore) >= 0.0 && parseFloat(cve.cveBaseScore) < 4
                                                                                                                            ? 'white'
                                                                                                                            : parseFloat(cve.cveBaseScore) >= 4 && parseFloat(cve.cveBaseScore) < 7
                                                                                                                            ? 'black'
                                                                                                                            : parseFloat(cve.cveBaseScore) >= 7 && parseFloat(cve.cveBaseScore) < 9
                                                                                                                            ? 'white'
                                                                                                                            : parseFloat(cve.cveBaseScore) >= 9 && parseFloat(cve.cveBaseScore) <= 10
                                                                                                                            ? 'white'
                                                                                                                            : 'black'
                                                                                                                    }}
                                                                                                                />
                                                                                                                <Typography
                                                                                                                    className={'serviceResultContentTypography'}>{cve.cveBaseScore || '-'}
                                                                                                                </Typography>
                                                                                                            </Stack>
                                                                                                            <br/>
                                                                                                            <Chip icon={<DescriptionIcon/>} label="Description" variant="outlined"/>
                                                                                                            <br/>
                                                                                                            <Typography>
                                                                                                                {cve.cveDesc}
                                                                                                            </Typography>
                                                                                                            </AccordionDetails>
                                                                                                    </Accordion>
                                                                                                </ListItem>
                                                                                            ))}
                                                                                        </div>
                                                                                    );
                                                                                }
                                                                            }
                                                                        }
                                                                    })}
                                                                </List>
                                                            </AccordionDetails>
                                                        </Accordion>
                                                    </div>
                                                </Paper>
                                            );
                                        })}
                                    </div>
                                    {/*  Service Graphs  */}
                                    {(() => {
                                        if (serviceChartArr.length > 0) {
                                            // Check if theres objects in the service chart array
                                            // Create Service Graph data
                                            const pieServiceVulnsData = {
                                                labels: serviceChartArr.map((data) => data.serviceName),
                                                // datasets is an array of objects where each object represents a set of data to display corresponding to the labels above.
                                                datasets: [
                                                    {
                                                        label: 'Number of CVEs',
                                                        data: serviceChartArr.map((data) => data.totalResults),
                                                        // you can set indiviual colors for each bar
                                                        backgroundColor: serviceChartArr.map(() => randomRGB()),
                                                        borderColor: "black",
                                                        borderWidth: 1,
                                                    }
                                                ]
                                            }

                                            const options = {
                                                plugins: {
                                                    title: {
                                                        display: true,
                                                        text: 'Discovered Services With CVEs',
                                                        maintainAspectRatio: false, // Disable aspect ratio
                                                        responsive: false, // Disable responsiveness
                                                    }
                                                }
                                            }

                                            return (
                                                <div className={'chartServiceContainer'}>
                                                    <Pie  data={pieServiceVulnsData} options={options} className={'pieChartServiceVulns'}/>
                                                </div>
                                            )
                                        }
                                    })()}
                                </AccordionDetails>
                            </Accordion>
                        );
                    })}
                </div>
            </div>
            <div className={'recommendations'}>
                <Accordion elevation={5} defaultExpanded={true}>
                    <AccordionSummary
                        expandIcon={<ExpandMoreIcon/>}
                    >
                        <Typography variant={"h6"}>Final Report</Typography>
                    </AccordionSummary>
                    {(() => {
                        let finalResult = [];  // Array containing IP addresses with CVEs

                        for (const cveItem of CVEInfo) {
                            const ipAddr = cveItem.address;
                            let serviceArr = [];

                            for (const serviceItem of cveItem.cveResults) {
                                const serviceName = serviceItem.serviceName;
                                const totalCve = serviceItem.cveTotalResults;

                                if (serviceItem.cveData.length > 0) {
                                    // This service has atleast one CVE

                                    serviceArr.push({
                                        "serviceName": serviceName,
                                        "cveData": serviceItem.cveData
                                    });
                                }
                            }
                            if (serviceArr.length > 0) {
                                finalResult.push({
                                    "ip": ipAddr,
                                    "cveData": serviceArr
                                })
                            }
                        }

                        return (
                            <div>
                                {
                                    finalResult.length > 0 ? (
                                        // Atleast one IP has a CVE
                                        <div className={'finalResult'}>
                                            <div className={'finalResultContent'}>
                                                <div className={'finalResultTextInformation'}>
                                                    <Typography>
                                                        The following CVEs were discovered on the devices below.
                                                        It is recommended to update every service affected in order to reduce the
                                                        likelihood of a machine becoming compromised.

                                                        <br/><br/>

                                                        General tips to update your services:
                                                        <br/><br/>
                                                        <b>Windows:</b> <br/>
                                                        <b>1.</b> Navigate to the services web page<br/>
                                                        <b>2.</b> Download the latest version<br/>
                                                        <b>3.</b> Uninstall outdated version<br/>
                                                        <b>4.</b> Install new version<br/>
                                                        <br/><br/>
                                                        <b>Unix:</b><br/>
                                                        Red Hat Distributions (RHEL, Fedora, CentOS, etc):<br/>
                                                        <b>1.</b> sudo yum update && sudo yum upgrade<br/>
                                                        This command updates the package index files, then upgrades the installed packages.<br/>
                                                        <br/><br/>
                                                        Debian Based Distributions (Ubuntu, Debian, etc):<br/>
                                                        <b>1.</b> sudo apt update && sudo yum upgrade<br/>
                                                        This command updates the package index files, then upgrades the installed packages.<br/>
                                                    </Typography>
                                                </div>

                                                {finalResult.map((item, index) => (
                                                    <Paper  elevation={6} className={'finalResultPapers'}>
                                                        <Typography variant={"h5"}>
                                                            IP Address: {item.ip}
                                                        </Typography>
                                                        <List key={index}
                                                             sx={{
                                                                 width: '100%',
                                                                 // maxWidth: 500,
                                                                 bgcolor: 'background.paper',
                                                                 position: 'relative',
                                                                 overflow: 'auto',
                                                                 maxHeight: 300,
                                                                 '& ul': {padding: 0},
                                                        }}>
                                                            {item.cveData.map((servicesArrItem: any, index: any) => (
                                                                <div key={index}>
                                                                    <ListSubheader key={index}>
                                                                        <Typography variant={"h6"}>
                                                                            Service: {servicesArrItem.serviceName}
                                                                        </Typography>
                                                                    </ListSubheader>
                                                                    {servicesArrItem.cveData
                                                                        .sort((a: any, b: any) => b.cveBaseScore - a.cveBaseScore)  // Sort in descending order
                                                                        .map((cveDataItem: any, index: any) => (
                                                                            <ListItem key={index} className={'finalResultListItem'}>
                                                                                <Stack direction="column" spacing={2}>
                                                                                    <Typography>
                                                                                        <b>CVE ID: </b> {cveDataItem.cveID}
                                                                                    </Typography>
                                                                                    <Stack direction="row" spacing={3}>
                                                                                        <Chip
                                                                                            icon={<NumbersIcon/>}
                                                                                            label="Base Score"
                                                                                            variant="outlined"
                                                                                            style={{
                                                                                                backgroundColor:
                                                                                                    parseFloat(cveDataItem.cveBaseScore) >= 0.0 && parseFloat(cveDataItem.cveBaseScore) < 4
                                                                                                        ? 'green'
                                                                                                        : parseFloat(cveDataItem.cveBaseScore) >= 4 && parseFloat(cveDataItem.cveBaseScore) < 7
                                                                                                        ? 'yellow'
                                                                                                        : parseFloat(cveDataItem.cveBaseScore) >= 7 && parseFloat(cveDataItem.cveBaseScore) < 9
                                                                                                            ? 'red'
                                                                                                            : parseFloat(cveDataItem.cveBaseScore) >= 9 && parseFloat(cveDataItem.cveBaseScore) <= 10
                                                                                                                ? 'black'
                                                                                                                : '',
                                                                                                color:
                                                                                                    parseFloat(cveDataItem.cveBaseScore) >= 0.0 && parseFloat(cveDataItem.cveBaseScore) < 4
                                                                                                        ? 'white'
                                                                                                        : parseFloat(cveDataItem.cveBaseScore) >= 4 && parseFloat(cveDataItem.cveBaseScore) < 7
                                                                                                        ? 'black'
                                                                                                        : parseFloat(cveDataItem.cveBaseScore) >= 7 && parseFloat(cveDataItem.cveBaseScore) < 9
                                                                                                            ? 'white'
                                                                                                            : parseFloat(cveDataItem.cveBaseScore) >= 9 && parseFloat(cveDataItem.cveBaseScore) <= 10
                                                                                                                ? 'white'
                                                                                                                : 'black'
                                                                                            }}
                                                                                        />
                                                                                        <Typography
                                                                                            className={'serviceResultContentTypography'}>
                                                                                            {cveDataItem.cveBaseScore}
                                                                                        </Typography>
                                                                                    </Stack>
                                                                                </Stack>
                                                                            </ListItem>
                                                                        ))}
                                                                </div>
                                                            ))}
                                                        </List>
                                                    </Paper>
                                                ))}
                                            </div>

                                            {/* IP graphs */}
                                            <div className={'finalResultGraphs'}>
                                                {(() => {
                                                    if (ipChartArr.length > 0) {
                                                        if (ipChartArr.some((data) => data.totalCve > 0)) {

                                                            console.log('Chart Array: ', JSON.stringify(ipChartArr));


                                                            const options = {
                                                                plugins: {
                                                                    title: {
                                                                        display: true,
                                                                        text: 'Discovered IPs With CVEs'
                                                                    }
                                                                }
                                                            }

                                                            // Create Service Graph data
                                                            const pieIpVulnsData = {
                                                                labels: ipChartArr
                                                                    .filter(data => data.totalCve > 0)
                                                                    .map(data => data.ip),
                                                                // datasets is an array of objects where each object represents a set of data to display corresponding to the labels above.
                                                                datasets: [
                                                                    {
                                                                        label: 'Number of CVEs',
                                                                        data: ipChartArr
                                                                            .filter(data => data.totalCve > 0)
                                                                            .map(data => data.totalCve),
                                                                        // you can set indiviual colors for each bar
                                                                        backgroundColor: ipChartArr
                                                                            .filter(data => data.totalCve > 0)
                                                                            .map(() => randomRGB()),
                                                                        borderColor: "black",
                                                                        borderWidth: 1,
                                                                    }
                                                                ]
                                                            }

                                                            return (
                                                                <div className={'chartIpContainer'}>
                                                                    <Pie data={pieIpVulnsData} options={options}
                                                                         className={'pieChartServiceVulns'}/>
                                                                </div>
                                                            )
                                                        }
                                                    }
                                                })()}
                                            </div>
                                        </div>

                                    ) : (
                                        // No IP's have CVEs
                                        <div className={'finalResultTextInformation'}>
                                            <Typography>
                                                The services on your network have <b>NO</b> vulnerabilities! Ensure you keep
                                                your services up to date.

                                                <br/><br/>

                                                General tips to update your services:
                                                <br/><br/>

                                                <b>Windows:</b> <br/>
                                                <b>1.</b> Navigate to the services web page<br/>
                                                <b>2.</b> Download the latest version<br/>
                                                <b>3.</b> Uninstall outdated version<br/>
                                                <b>4.</b> Install new version<br/>
                                                <br/><br/>
                                                <b>Unix:</b><br/>
                                                Red Hat Distributions (RHEL, Fedora, CentOS, etc):<br/>
                                                <b>1.</b> sudo yum update && sudo yum upgrade<br/>
                                                This command updates the package index files, then upgrades the installed packages.<br/>
                                                <br/><br/>
                                                Debian Based Distributions (Ubuntu, Debian, etc):<br/>
                                                <b>1.</b> sudo apt update && sudo yum upgrade<br/>
                                                This command updates the package index files, then upgrades the installed packages.<br/>
                                            </Typography>
                                        </div>
                                    )
                                }
                            </div>
                        )
                    })()}
                </Accordion>
            </div>
        </Paper>
    );

    await updateScanResult(scanResultsArray, setScanResultsArray, cveScanResult);

    // Scan is complete, allow the button to be clicked again
    setLoading(false);
}

async function callCVE(servicesResult: string) {
    return await window.electron.ipcRenderer.scanCVE(servicesResult)
}

async function updateScanResult(scanResultsArray: any[], setScanResultsArray: any, scanResultToUpdate: any) {
    await setScanResultsArray((prevState: any[]) => {
        if (prevState.length === 0) {
            // If scanResultsArray is empty, add the new scan result directly to the array
            return [scanResultToUpdate];
        } else {
            // Create a new array based on the updated value and existing content
            const updatedArray = prevState.map((scanResult, index) => {
                if (index === prevState.length - 1) {
                    // Simply returns the array item to update if the existing array is empty
                    return scanResultToUpdate;
                } else {
                    // Crates a new array with the item to update
                    const lastIndex = prevState.length - 1;
                    const updatedArrayy = [...prevState];
                    updatedArray[lastIndex] = scanResultToUpdate;
                    return updatedArrayy;
                }
            });
            return updatedArray.reverse();
        }
    });
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Main />} />
      </Routes>
    </Router>
  );
}

