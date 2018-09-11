//=============================================================================
//
// File:         rwserve-brute-force/src/index.js
// Language:     ECMAScript 2015
// Copyright:    Read Write Tools © 2018
// License:      MIT License
// Initial date: Aug 25, 2018
//
// Contents:     An RWSERVE plugin to temporarily blacklist an IP address that 
//               attempts to POST too many times in a given period. This is  
//               well suited to blocking brute-force attacks on login pages.
//               
//               Visitors are allowed a specified number of 'visits' during a
//               defined 'grace-period' before being blocked with a status of 403
//               for a defined 'blackout-period'.
//
//======================== Sample configuration ===============================
/*
	plugins {
		rwserve-brute-force {
			location `/srv/rwserve-plugins/rwserve-brute-force.class.js`
			config {
				max-visits      5      // number of attempts allowed before being blocked  	
				grace-period    300    // number of seconds before resetting visit counter
				blackout-period 900    // duration of blackout period (in seconds)
				log-failures    true   // true to log failed attempts; false to remain silent
			}
		}
		router {
			`/login`  *methods=POST  *plugin=rwserve-brute-force
		}	
	}
*/
//======================== CURL test ==========================================
//
// curl -X POST https://localhost:7443/rbac/credentials/login -H content-type:application/x-www-form-urlencoded -H content-length:36 -d "action=login&user=root&password=root"
//
//=============================================================================
	
import {log} 		from 'rwserve-plugin-sdk';
import {SC} 		from 'rwserve-plugin-sdk';

class BruteForceData {
	constructor() {
		this.firstVisit = Date.now();
		this.counter = 1;
	}
}

export default class RwserveBruteForce {

	constructor(hostConfig) {
		this.hostConfig = hostConfig;
		this.bruteForceConfig = hostConfig.pluginsConfig.rwserveBruteForce;		

		this.maxVisits      = 0;
		this.gracePeriod    = 0;
		this.blackoutPeriod = 0;
		this.logFailures    = 'false';
		
		this.ipMap = new Map();										// key is IpAddress, value is a BruteForceStruct
		this.cleanupPeriodicity = (15*60*1000);						// 15 minutes
		this.nextCleanup = Date.now() + this.cleanupPeriodicity;	// next time a cleanup operation should be performed
		
    	Object.seal(this);
	}
	
	async startup() {
		log.debug('RwserveBruteForce', 'v1.0.0; © 2018 Read Write Tools; MIT License');
		
		// sanitize, using fallbacks if necessary
		this.maxVisits = parseInt(this.bruteForceConfig.maxVisits);
		if (isNaN(this.maxVisits) || this.maxVisits < 1 || this.maxVisits > 100)
			this.maxVisits = 1;															// default to 1 visit only

		this.gracePeriod = parseInt(this.bruteForceConfig.gracePeriod) * 1000;			// convert seconds to milliseconds
		if (isNaN(this.gracePeriod) || this.gracePeriod < 1000)
			this.gracePeriod = 1000;													// default to 1 second grace period

		this.blackoutPeriod = parseInt(this.bruteForceConfig.blackoutPeriod) * 1000;	// convert seconds to milliseconds
		if (isNaN(this.blackoutPeriod) || this.blackoutPeriod < 1000)
			this.blackoutPeriod = (60*1000);											// default to 60 second grace period

		this.logFailures = this.bruteForceConfig.logFailures;
		if (this.logFailures == 'true')
			this.logFailures = true;
		else
			this.logFailures = false;
	}
	
	async shutdown() {
		log.debug('RwserveBruteForce', `Shutting down ${this.hostConfig.hostname}`); 
	}
	
	// This is the main entry point called by RWSERVE for each request/response
	async processingSequence(workOrder) {
		try {
			var ipAddress = workOrder.getRemoteAddress();
			if (this.ipMap.has(ipAddress)) {
				this.returningVisitor(workOrder, ipAddress);
			}
			else {
				// add new visitors to the map with a count of 1
				var bruteForceData = new BruteForceData();
				this.ipMap.set(ipAddress, bruteForceData);
			}
			
			this.cleanup();
		}
		catch (err) {
			log.error(err.message);
		}
	}
	
	returningVisitor(workOrder, ipAddress) {		
		// get the existing data for this ip address
		var bruteForceData = this.ipMap.get(ipAddress);
		
		// check to see if this is an old record that expired while in grace
		if ((bruteForceData.firstVisit + this.gracePeriod) < Date.now() && (bruteForceData.counter <= this.maxVisits)) {
			// reset the data
			bruteForceData.firstVisit = Date.now();
			bruteForceData.counter = 1;
			return;
		}
		
		// check to see if this is an old record that expired while in blackout
		if ((bruteForceData.firstVisit + this.gracePeriod + this.blackoutPeriod) < Date.now()) {
			// reset the data
			bruteForceData.firstVisit = Date.now();
			bruteForceData.counter = 1;
			return;
		}
		
		// increment the counter for this IP address
		bruteForceData.counter++;

		// check to see if it exceeds the threshold
		if (bruteForceData.counter > this.maxVisits) {			
			workOrder.setStatusCode(SC.FORBIDDEN_403);
			workOrder.setEmptyPayload();			
			if (this.logFailures)
				log.error(`RwserveBruteForce RA=${ipAddress}; CT=${bruteForceData.counter}`);
		}
	}
	
	// remove entries from the IP map if they are older than gracePeriod or blackoutPeriod
	cleanup() {		
		// not time for a cleanup yet, skip
		var now = Date.now();
		if (now <  this.nextCleanup)
			return;
		
		for (let [key, value] of this.ipMap) {
			var bruteForceData = this.ipMap.get(key);
			
			// if the grace period has not yet ended, keep this record in memory
			if ((bruteForceData.firstVisit + this.gracePeriod) > now)
				continue;
			
			// check to see if this is an old record that expired while in grace
			else if ((bruteForceData.firstVisit + this.gracePeriod) <= now && (bruteForceData.counter <= this.maxVisits))
				this.ipMap.delete(key);
				
			// if the blackout period has not yet ended, keep this record in memory
			else if ((bruteForceData.firstVisit + this.gracePeriod + this.blackoutPeriod) > now)
				continue;
			
			// this guy was in blackout, but it has elapsed, now allow him to try again
			else
				this.ipMap.delete(key);
		}
		
		// reset timout
		this.nextCleanup = Date.now() + this.cleanupPeriodicity;
	}
}
