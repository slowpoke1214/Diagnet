import '@testing-library/jest-dom';
import {getByTestId, render, screen} from '@testing-library/react';
import App from '../renderer/App';
import {scanCVE} from "../main/scanner";

// Test results for the CVE function
const servicesResult = [{
  "192.168.1.13": {
    "os": ["Linux 4.15 - 5.6"],
    "ports": [{
      "OpenSSH": {
        "CPE": "cpe:/a:openbsd:openssh:8.2p1",
        "port": "22",
        "version": "8.2p1 Ubuntu 4ubuntu0.5"
      }}]
  }
}]

describe('App', () => {
  it('should render', () => {
    expect(render(<App />)).toBeTruthy();

  });

  it('should render the information on the main page',  () => {
    // Tests the contents of the homepage, ensuring that the application can be properly rendered
    expect(render(<App />)).toBeTruthy();
    expect(screen.getByText('Diagnet is a lightweight and easy to use network scanner, ' +
        'capable of determining online hosts, service and operating system information, and ' +
        'relevant Common Vulnerabilities and Exposures (CVE\'s) associated with discovered services. ' +
        'To begin scanning, press the button below.')).toBeInTheDocument();

    expect(screen.getByText('Diagnet')).toBeInTheDocument();
    expect(screen.getByText('This product uses data from the NVD API but is not endorsed or ' +
        'certified by the NVD')).toBeInTheDocument();

  });
});