import { MemoryRouter as Router, Routes, Route } from 'react-router-dom';
import icon from '../../assets/icon.svg';
import './App.css';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';


import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import Typography from '@mui/material/Typography';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {json} from "stream/consumers";
import {useState} from "react";
// import Card from '@mui/material/Card';

function Main() {
    const [scanResultsArray, setScanResultsArray] = useState([]);

    return (
      <div>
          <Button variant={"outlined"}
            onClick={() => {
                try {
                    scanner(scanResultsArray, setScanResultsArray).then(r => {
                    });
                } catch (e) {
                    console.log(e)
                }
            }}
          >
              Nice
          </Button>

          {scanResultsArray.map((scanResult, index) => (
              <div key={index}>
                  {scanResult}
              </div>
          ))}
      </div>
  );
}

async function scanner(scanResultsArray, setScanResultsArray) {
    // This function Should asynchronously handle receiving every step

    // TODO: Change button to cancel, and listen for a cancellation

    // TODO: Create a paper with a unique id, as well for the accordions
    //  in it, then when the second phase of port scanning is done you
    //  can target the unique ID and add to it

    /*
        ---------DEVICE SCAN---------
    */
    const devices = await window.electron.ipcRenderer.scanDevices();
    console.log(devices);

    const scanResult = (
        <Paper>
            <div className={'paperTitle'}>
                Title
            </div>

            <div className={'paperContent'}>
                <Accordion>
                    <AccordionSummary
                        expandIcon={<ExpandMoreIcon />}
                        aria-controls="panel1a-content"
                        id="panel1a-header"
                    >
                        <Typography>Network Discovery 1</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography>
                            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse
                            malesuada lacus ex, sit amet blandit leo lobortis eget.
                        </Typography>
                    </AccordionDetails>
                </Accordion>
            </div>
        </Paper>
    );

    await setScanResultsArray((prevState: any) => [...prevState, scanResult]);

    const otherResult = (
        <Paper>
            <div className={'paperrTitle'}>
                Title
            </div>

            <div className={'paperrContent'}>
                <Accordion>
                    <AccordionSummary
                        expandIcon={<ExpandMoreIcon />}
                        aria-controls="panel1a-content"
                        id="panel1a-header"
                    >
                        <Typography>Network Discovery 2</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography>
                            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Suspendisse
                            malesuada lacus ex, sit amet blandit leo lobortis eget.
                        </Typography>
                    </AccordionDetails>
                </Accordion>
            </div>
        </Paper>
    );

    await setScanResultsArray((prevState: any) => [...prevState, otherResult]);


    /*
        ---------OS and PORT SCAN---------
    */
    try {
        var ports = await window.electron.ipcRenderer.scanPorts(devices);
    } catch (e) {
        console.log('Error in scanning ports: ' + e);
    }
    console.log(ports)

    const portsScanResult = (
        <Paper>
            <div className={'paperTitle'}>
                Title
            </div>

            <div className={'paperContent'}>
                <Accordion>
                    <AccordionSummary
                        expandIcon={<ExpandMoreIcon />}
                        aria-controls="panel1a-content"
                        id="panel1a-header"
                    >
                        <Typography>Network Discovery 2 - Changed</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Typography>
                            NEW CONTENT PLS
                        </Typography>
                    </AccordionDetails>
                </Accordion>
            </div>
        </Paper>
    );

    await updateScanResult(scanResultsArray, setScanResultsArray, portsScanResult)

    /*
        ---------SERVICE SCAN---------
    */
    const services = await window.electron.ipcRenderer.scanServices();
    console.log(services)
}

async function updateScanResult(scanResultsArray: any[], setScanResultsArray, scanResultToUpdate: any) {
    await setScanResultsArray(prevState => {
        if (prevState.length === 0) {
            // If scanResultsArray is empty, add the new scan result directly to the array
            return [scanResultToUpdate];
        } else {
            // find the index of the most recent Paper component
            const lastIndex = prevState.length - 1;

            // create a new array with the most recent Paper component updated
            const updatedArray = prevState.map((scanResult, index) => {
                if (index === lastIndex) {
                    return scanResultToUpdate;
                } else {
                    return scanResult;
                }
            });

            return updatedArray;
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

