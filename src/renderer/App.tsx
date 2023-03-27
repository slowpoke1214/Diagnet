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

import LoadingButton from '@mui/lab/LoadingButton';

import SensorsIcon from '@mui/icons-material/Sensors';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
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
            label: 'Scanning each discovered device for active services on open ports',
            description:
                'this scan takes a while.',
        },
        {
            label: 'Using NIST National Vulnerability Database (NVD) API to check for any known vulnerabilities',
            description: `This takes approximately 6 seconds / service`,
        },
    ];


    const scanResult = (
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

    await setScanResultsArray((prevState: any) => [...prevState, scanResult]);
    setLoading(false);

    // const otherResult = (
    //     <Paper>
    //         <div className={'paperrTitle'}>
    //             Title
    //         </div>
    //
    //         <div className={'paperrContent'}>
    //             <Accordion>
    //                 <AccordionSummary
    //                     expandIcon={<ExpandMoreIcon />}
    //                     aria-controls="panel1a-content"
    //                     id="panel1a-header"
    //                 >
    //                     <Typography>Network Discovery 2</Typography>
    //                 </AccordionSummary>
    //                 <AccordionDetails>
    //                     <Typography>
    //                         Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse
    //                         malesuada lacus ex, sit amet blandit leo lobortis eget.
    //                     </Typography>
    //                 </AccordionDetails>
    //             </Accordion>
    //         </div>
    //     </Paper>
    // );

    // await setScanResultsArray((prevState: any) => [...prevState, otherResult]);


    /*
        ---------OS and PORT SCAN---------
    */
    try {
        var ports = await window.electron.ipcRenderer.scanPorts(devices);
    } catch (e) {
        console.log('Error in scanning ports: ' + e);
    }
    console.log(ports)

    // const portsScanResult = (
    //     <Paper>
    //         <div className={'paperTitle'}>
    //             Title
    //         </div>
    //
    //         <div className={'paperContent'}>
    //             <Accordion>
    //                 <AccordionSummary
    //                     expandIcon={<ExpandMoreIcon />}
    //                     aria-controls="panel1a-content"
    //                     id="panel1a-header"
    //                 >
    //                     <Typography>Network Discovery 2 - Changed</Typography>
    //                 </AccordionSummary>
    //                 <AccordionDetails>
    //                     <Typography>
    //
    //                         NEW CONTENT PLS
    //                     </Typography>
    //                 </AccordionDetails>
    //             </Accordion>
    //         </div>
    //     </Paper>
    // );
    //
    // await updateScanResult(scanResultsArray, setScanResultsArray, portsScanResult)

    /*
        ---------SERVICE SCAN---------
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
                    return scanResult;
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

