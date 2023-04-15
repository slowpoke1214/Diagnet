import {json} from "stream/consumers";

const { Worker } =  require('worker_threads');
const { networkInterfaces } = require('os');
const { promisify } = require('util');
const net = require('net');
const ping = require('ping');
const nmap = require('node-nmap');
const libnmapp = require('libnmap');
nmap.nmapLocation = 'nmap';

export async function scanDevices() : Promise<unknown> {
    // Call function to retrieve primary IP address from local interfaces
    const IP = await getLocalIP();

    if (IP == 'ipNotFound') {
        // Check if the IP could not be identified
        return IP;
    }

    // Split the IP into netmask and IP address
    const ipAddress = IP.split(':')[0];
    const netmask = IP.split(':')[1];

    // Split the IP and netmask parts further for creating the range
    const addressParts = ipAddress.split('.');
    const netmaskParts = netmask.split('.');
    const netAddress = addressParts.map((part, i) => parseInt(part) & parseInt(netmaskParts[i])).join('.');
    const range = `${netAddress.substring(0, netAddress.lastIndexOf('.'))}.1-254`;
    const ipAddresses: string[] = [];

    let nmapscan = new nmap.QuickScan(range);
    const nmapPromise = new Promise((resolve, reject) => {
        nmapscan.on('complete', function (data: any) {
            for (let i = 0; i < data.length; i++) {
                // Iterate through results of scan
                if (data[i].mac) {
                    // Verify that the addresses are correct and have a mac address
                    ipAddresses.push(data[i].ip)
                }
            }
            // Resolve the promise with the array of discovered IP addresses
            resolve(ipAddresses);
        });

        nmapscan.on('error', function (error: any) {
            console.log(error);
            reject(error);
        });
    });

    nmapscan.startScan(); // Start the nmap scan
    let nmapScanResult = await nmapPromise; // Wait for the promise to resolve

    console.log('Scanning devices time: ', nmapscan.scanTime);
    return nmapScanResult;
}

export async function scanPorts(event: any, devices: string) : Promise<unknown> {
    // TODO: Scan ports and return output
    let mainList: string[] = [];
    for (let i = 0; i < devices.length; i++) {
        mainList.push(devices[i]);
    }

    const opts = {
        flags: [
            '-sV', // Scans open ports to determine service
            '-O', // OS finger printing
            // '-sC',
        ],
        range: mainList,
        json: true
    };

    const nmapPromise = new Promise((resolve, reject) => {
        libnmapp.scan(opts, function(err: any, report: any) {
            if (err) throw err;
            let results = []

            for (const item in report) {
                const host = report[item];
                const hostArr = host.host

                // Do something with each item in the host array
                for (const hostItem of hostArr) {
                    const addressArr = hostItem.address;
                    const portsArr = hostItem.ports;
                    const osArr = hostItem.os;

                    for (const addressItem of addressArr) {
                        const addr = addressItem.item.addr;

                        if (mainList.includes(addr)) {
                            // Address matches

                            let serviceResults = []

                            let osName = null

                            try {
                                for (const osArrItem of osArr) {
                                    const osMatchArr = osArrItem.osmatch;

                                    if (osMatchArr[0].item.name) {
                                        osName = osMatchArr[0].item.name;
                                    }
                                }
                            } catch (e) {
                                // Ignore any values that aren't found
                            }

                            try {
                                // Ports Iteration
                                for (const portsArrItem of portsArr) {
                                    // Port number
                                    // Service Name
                                    // CPE

                                    // Reset the service results for this iteration
                                    serviceResults = []

                                    const mainPortsArr = portsArrItem.port;
                                    for (const mainPortsArrItem of mainPortsArr) {
                                        const serviceArr = mainPortsArrItem.service;

                                        // Initialize the values
                                        let serviceCPE = null;
                                        let serviceVersion = null;
                                        let serviceName = null;
                                        let servicePort = null;

                                        if (mainPortsArrItem.item.portid) {
                                            servicePort = mainPortsArrItem.item.portid;
                                        }

                                        for (const serviceArrItem of serviceArr) {
                                            if (serviceArrItem.item.version) {
                                                serviceCPE = serviceArrItem.cpe[0];
                                                serviceVersion = serviceArrItem.item.version;
                                            }

                                            if (serviceArrItem.item.product) {
                                                serviceName = serviceArrItem.item.product;
                                            }
                                            serviceResults.push({[serviceName]: {'CPE': serviceCPE, 'version': serviceVersion, 'port': servicePort}})
                                        }
                                    }
                                }
                            } catch (e) {
                                // Ignore any values that aren't found
                            }
                            results.push({[addr]: {'ports': serviceResults, 'os': [osName]}})
                        }
                    }
                }
            }

            resolve(JSON.stringify(results));
        });
    });
    let nmapScanResult = await nmapPromise; // Wait for the promise to resolve
    return nmapScanResult;
}

export async function scanCVE(event: any, CVEDeviceInfo: string) : Promise<unknown> {
    // TODO: Use NIST NVD API to check for CVE

    const NISTUrl = 'https://services.nvd.nist.gov/rest/json/cves/1.0/';
    const cpeNameParam = '?cpeName=';
    const results = [];

    const deviceInfo = JSON.parse(CVEDeviceInfo);
    // Loop over items
    for (const data of deviceInfo) {
        // Take JSON object from the array
        for (const addr of Object.keys(data)) {
            // Iterate each JSON key/value pair

            const servicesArr = [];
            for (const service of data[addr].ports) {
                // Iterate through each service in the address

                const serviceName = Object.keys(service)[0] || null
                // Check if service exists
                if (serviceName) {
                    let cpeResult;
                    const cpe = service[serviceName].CPE || null;
                    // Check if the CPE is set
                    if (cpe) {
                        // CPE Exists, use API
                        const res = await fetch(`${NISTUrl}${cpeNameParam}${encodeURIComponent(cpe)}`);
                        cpeResult = await res.json();

                        // Timeout for 6 seconds due to rate limiting by NIST API
                        await new Promise(resolve => setTimeout(resolve, 6000));

                    } else {
                        // CPE has not been set
                        cpeResult = [];
                    }

                    // Add to results array
                    servicesArr.push({
                        "serviceName": serviceName,
                        "CVEData": cpeResult
                    })
                }
            }
            // End of address, add to list
            results.push({
                "address": addr,
                "data": servicesArr
            })
        }

    }

    const mainResults = [];
    // console.log('---- CVE Results Array ----', JSON.stringify(results))

    // for (const items of testResults) {
    for (const items of results) {
        // Iterate through each IP address
        const addr = items.address ?? null;
        const cveServicesArr = [];
        // console.log('---- At Current IP ----:', addr);

        for (const serviceData of items.data) {
            // Iterate through each services CVE information
            const cveDataArr = [];

            const serviceName = serviceData.serviceName ?? null;
            const numResults = serviceData.CVEData.totalResults ?? null;
            // console.log('---- At Current Service Data ----', JSON.stringify(serviceData));

            if (serviceData.CVEData?.result?.CVE_Items !== undefined) {
                console.log(serviceData.CVEData.result.CVE_Items.length);
                for (const cveItems of serviceData.CVEData.result.CVE_Items) {
                    // Iterate through each CVE

                    const cveID = cveItems.cve.CVE_data_meta.ID ?? null;
                    let cveScore = null;
                    // const cveScore = cveItems.impact.baseMetricV3.cvssV3.baseScore ?? null;
                    if (cveItems.impact.baseMetricV3) {
                        cveScore = cveItems.impact.baseMetricV3.cvssV3.baseScore;
                    } else if (cveItems.impact.baseMetricV2) {
                        cveScore = cveItems.impact.baseMetricV2.cvssV2.baseScore;
                    }
                    const cveDesc = cveItems.cve.description.description_data[0].value ?? null;

                    cveDataArr.push({
                        "cveID": cveID,
                        "cveBaseScore": cveScore,
                        "cveDesc": cveDesc
                    })
                }
            }
            // Add the service and its CVE info to the array
            cveServicesArr.push({
                "serviceName": serviceName,
                "cveTotalResults": numResults,
                "cveData": cveDataArr
            })
        }
        // Add the address with its services to the results array
        mainResults.push({
            "address": addr,
            "cveResults": cveServicesArr
        })
    }
    return JSON.stringify(mainResults);
}

async function getLocalIP() {
    const interfaces = networkInterfaces();
    let discoveredIP = null;

    // Iterate through all network interfaces
    for (const name of Object.keys(interfaces)) {
        const iface = interfaces[name];

        // Check if the interface is associated with a virtual machine
        if (name.toLocaleLowerCase().startsWith('virtual') || name.toLocaleLowerCase().startsWith('vm') || name.toLocaleLowerCase().startsWith('vbox')) {
            continue;
        }
        // Iterate through list of IP addresses associated with the interface
        for (const address of iface) {
            if (address.family === 'IPv4' && !address.internal && address.mac !== '00:00:00:00:00:00' && address.netmask === '255.255.255.0') {
                discoveredIP = address.address + ":" + address.netmask;
                break;
            }
        }
        if (discoveredIP) {
            break;
        }
    }
    if (!discoveredIP) {
        // An Interface could not be found
        // TODO: Handle error
        return 'ipNotFound'
    }
    return discoveredIP;
}