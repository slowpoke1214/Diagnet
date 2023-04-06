import { MemoryRouter as Router, Routes, Route } from 'react-router-dom';
import icon from '../../assets/icon.svg';
import './App.css';

import Button from '@mui/material/Button';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import Paper from '@mui/material/Paper';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
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

import LoadingButton from '@mui/lab/LoadingButton';

import SensorsIcon from '@mui/icons-material/Sensors';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import NumbersIcon from '@mui/icons-material/Numbers';
import ManageHistoryIcon from '@mui/icons-material/ManageHistory';
import InfoIcon from '@mui/icons-material/Info';
import DescriptionIcon from '@mui/icons-material/Description';
import ScoreIcon from '@mui/icons-material/Score';
import MenuIcon from '@mui/icons-material/Menu';

import {json} from "stream/consumers";
import {useState} from "react";
// import Card from '@mui/material/Card';

function Main() {
    const [scanResultsArray, setScanResultsArray] = useState([]);
    const [loadingBool, setLoading] = useState(false);


    // Test variables
    const currDate = new Date().toLocaleDateString();
    const currTime = new Date().toLocaleTimeString();
    const devices = [
        '192.168.1.1',   '192.168.1.11',
        '192.168.1.69',  '192.168.1.103',
        '192.168.1.104', '192.168.1.111',
        '192.168.1.133', '192.168.1.161',
        '192.168.1.175', '192.168.1.13',
    ];

    return (
        // ----------Navbar----------
      <div>
          <Box sx={{ flexGrow: 1 }}>
              <AppBar position="static">
                  <Toolbar variant="dense">
                      <Typography variant="h5" color="inherit" component="div">
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
                      <span>Start Scan</span>
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

    // TODO: Change button to cancel, and listen for a cancellation

    // TODO: Create a paper with a unique id, as well for the accordions
    //  in it, then when the second phase of port scanning is done you
    //  can target the unique ID and add to it

    // Get current date and time
    const currDate = new Date().toLocaleDateString();
    const currTime = new Date().toLocaleTimeString();

    const steps = [
        {
            label: 'Scanning ports on discovered machines for active services',
            description:
                'This scan iterates through each discovered host, and checks ports 1-1024 for ' +
                'any services that are operational, then saves relevant information associated with them',
        },
        {
            label: 'Using NIST National Vulnerability Database (NVD) API to check for any known vulnerabilities using discovered information',
            description: `Using the publicly available NIST NVD API, the discovered service information is being used to determine if any 
            vulnerabilities exist. This step takes approximately 6 seconds / CPE`,
        },
        {
            label: 'Report Generation',
            description: `A report with the final suggestions according to the programs discoveries is created.`,
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

    // await setScanResultsArray((prevState: any) => [...prevState, startingResult]);
    await updateScanResult(scanResultsArray, setScanResultsArray, startingResult);

    /*
        ---------DEVICE SCAN---------
    */
    // Run device scan
    const devices = await window.electron.ipcRenderer.scanDevices();
    console.log(devices);


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
        // var servicesResult = JSON.parse(await window.electron.ipcRenderer.scanPorts(devices));
        servicesResult = [{
            "192.168.1.13": {
                "os": ["Linux 4.15 - 5.6"],
                "ports": [{
                    "OpenSSH": {
                        "CPE": "cpe:/a:openbsd:openssh:8.2p1",
                        "port": "22",
                        "version": "8.2p1 Ubuntu 4ubuntu0.5"
                    }
                }, {
                    "nginx": {
                        "CPE": "cpe:/a:igor_sysoev:nginx:1.18.0",
                        "port": "80",
                        "version": "1.18.0"
                    }
                }
                ]
            }, "192.168.1.69": {
                "os": ["Linux 1.15 - 5.6"],
                "ports": [{
                    "OpenSSH": {
                        "CPE": "cpe:/a:openbsd:openssh:8.2p1",
                        "port": "69",
                        "version": "8.2p1 Ubuntu 4ubuntu0.5"
                    }
                }, {
                    "nginx": {
                        "CPE": "cpe:/a:igor_sysoev:nginx:1.18.0",
                        "port": "96",
                        "version": "1.18.0"
                    }
                }
                ]
            }
        }]
    } catch (e) {
        console.log('Error in scanning ports: ' + e);
    }
    console.log('Entire Output:', servicesResult)
    // setLoading(false);

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

                        // console.log('MatchingItem: ', JSON.stringify(matchingItem));
                        // console.log('nicee:', ports);
                        // console.log('OS: ', os);

                        return (
                            <Accordion defaultExpanded={true} key={index}>
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

    // TODO:
    // - When displaying CVE ID, add href to the https://nvd.nist.gov/vuln/detail/ + CVE_ID
    // -

    let CVEInfo = await window.electron.ipcRenderer.scanCVE(JSON.stringify(servicesResult));
    CVEInfo = JSON.parse(CVEInfo);
    console.log('CVE INFO!: ',CVEInfo)

    const data = [
        { year: 2010, count: 10 },
        { year: 2011, count: 20 },
        { year: 2012, count: 15 },
        { year: 2013, count: 25 },
        { year: 2014, count: 22 },
        { year: 2015, count: 30 },
        { year: 2016, count: 28 },
    ];

    const cveScanResult = (
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
                        const os = matchingItem?.[item]?.os?.[0] ?? 'N/A'; // Nullish Coalescing operator to ensure value is not null or undefined

                        // console.log('MatchingItem: ', JSON.stringify(matchingItem));
                        // console.log('nicee:', ports);
                        // console.log('OS: ', os);

                        return (
                            <Accordion defaultExpanded={true} key={index}>
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
                                                        <Accordion defaultExpanded={true} key={index} elevation={5}>
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
                                </AccordionDetails>
                            </Accordion>
                        );
                    })}
                </div>
                // Create graphs

            </div>
        </Paper>
    );

    await updateScanResult(scanResultsArray, setScanResultsArray, cveScanResult);

    // Create graphs

    setLoading(false);
}

async function updateScanResult(scanResultsArray: any[], setScanResultsArray: any, scanResultToUpdate: any) {
    await setScanResultsArray((prevState: any[]) => {
        if (prevState.length === 0) {
            // If scanResultsArray is empty, add the new scan result directly to the array
            return [scanResultToUpdate];
        } else {
            // // find the index of the most recent Paper component
            // const lastIndex = prevState.length - 1;
            //
            // // create a new array with the most recent Paper component updated
            // const updatedArray = prevState.map((scanResult, index) => {
            //     if (index === lastIndex) {
            //         return scanResultToUpdate;
            //     } else {
            //         return scanResult;
            //     }
            // });
            //
            // return updatedArray;
            // create a new array with the most recent Paper component updated
            const updatedArray = prevState.map((scanResult, index) => {
                if (index === prevState.length - 1) {
                    return scanResultToUpdate;
                } else {
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

function displayResults() {
    const testComp = (
        <Paper elevation={6} square>
            <div>
                Title
            </div>

            <div>
                Acordian content
            </div>
        </Paper>
    )

    return testComp;
}

// window.electron.ipcRenderer.on('startScan', async (arg) => {
//     // eslint-disable-next-line no-console
//     if (arg == '200') {
//         console.log('200 received')
//         console.log(arg)
//     } else {
//         console.log('Error received')
//     }
// });

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Main />} />
      </Routes>
    </Router>
  );
}

