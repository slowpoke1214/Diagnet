import { MemoryRouter as Router, Routes, Route } from 'react-router-dom';
import icon from '../../assets/icon.svg';
import './App.css';

import Button from '@mui/material/Button';
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

import LoadingButton from '@mui/lab/LoadingButton';

import SensorsIcon from '@mui/icons-material/Sensors';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import NumbersIcon from '@mui/icons-material/Numbers';
import ManageHistoryIcon from '@mui/icons-material/ManageHistory';
import InfoIcon from '@mui/icons-material/Info';
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

    /*
        ---------DEVICE SCAN---------
    */
    // Run device scan
    const devices = await window.electron.ipcRenderer.scanDevices();
    console.log(devices);

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


    const deviceScanResult = (
        <Paper>
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
                        <Accordion key={index}>
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

    await setScanResultsArray((prevState: any) => [...prevState, deviceScanResult]);



    /*
        ---------OS and PORT SCAN---------
    */
    try {
        // var servicesResult = JSON.parse(await window.electron.ipcRenderer.scanPorts(devices));
        var servicesResult = [{
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
    console.log(servicesResult)
    setLoading(false);

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
                    {devices.map((item: any, index: any) => {
                        // Check for a match
                        const matchingItem = servicesResult.find((result) => result[item]);
                        const ports = matchingItem ? matchingItem[item].ports : [];
                        const os = matchingItem?.[item]?.os?.[0] ?? 'N/A'; // Nullish Coalescing operator to ensure value is not null or undefined

                        console.log('MatchingItem: ', JSON.stringify(matchingItem));
                        console.log('nicee:', ports);
                        console.log('OS: ', os);

                        return (
                            <Accordion expanded={true} key={index}>
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
    // const services = await window.electron.ipcRenderer.scanServices();
    // console.log(services)
}

async function updateScanResult(scanResultsArray: any[], setScanResultsArray, scanResultToUpdate: any) {
    await setScanResultsArray(prevState => {
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

