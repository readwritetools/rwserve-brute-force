







<figure>
	<img src='/img/plugins/brute-force/brute-force-pixaby-the-digital-way.jpg' width='100%' />
	<figcaption></figcaption>
</figure>

# Brute Force

## Detect and block repetitive POSTs


<address>
<img src='/img/rwtools.png' width=80 /> by <a href='https://readwritetools.com' title='Read Write Tools'>Read Write Tools</a> <time datetime=2018-10-22>Oct 22, 2018</time></address>



<table>
	<tr><th>Abstract</th></tr>
	<tr><td>This plugin detects repetitive attempts to POST to a given website resource. This is a sign of trouble for your website, as it may be an attempt to gain unauthorized access via weak user credentials. Further attempts are temporarily blocked until a specified blackout period has expired.</td></tr>
</table>

### Motivation

Attempts to circumvent your website's authorization process are a fact of life.
Detecting and dealing with them are necessary. One common hacking method is
simple brute force trial and error. When a series of unsuccessful requests to
login occurs in a short period of time, this plugin will add the user-agent's
remote address to a blacklist: subsequent requests to login will be blocked with
status code `403 Forbidden`.

Sometimes a legitimate user may trigger this detector and accidentally lock
themselves out. For this reason, the blackout is automatically removed after a
given period of time.

Often these cracking attempts will be routed through a botnet, where each
request comes from a large collection of different IP addresses.  For those
types of attacks, you can set the `max-visits` variable to a low value, to detect
and block attempts aggressively.

In order to monitor the usefulness of this plugin you can enable the `log-failures`
configuration switch. When `true` the IP address of each blocked request will be
printed to the website's log.

#### Customization

This plugin is open source and can be modified or enhanced to perform tasks such
as these:

   * Permanently block IP addresses that request a *honeypot* resource.
   * Redirect a blacklisted user via `303 See Other` to a customer service help page.
   * Detect *botnet thunderstorms* and automatically increase threshold sensitivity.

### Download

The plugin module is available from <a href='https://www.npmjs.com/package/rwserve-brute-force'>NPM</a>
. Before proceeding, you should already have `Node.js` and `RWSERVE` configured and
tested.

This module should be installed on your web server in a well-defined place, so
that it can be discovered by `RWSERVE`. The standard place for public domain
plugins is `/srv/rwserve-plugins`.

<pre>
cd /srv/rwserve-plugins
npm install rwserve-brute-force
</pre>

### Configuration is Everything

Make the software available by declaring it in the `plugins` section of your
configuration file. For detailed instructions on how to do this, refer to the <a href='https://rwserve.readwritetools.com/plugins.blue'>plugins</a>
documentation on the `Read Write Tools HTTP/2 Server` website.

#### TL;DR

<pre>
plugins {
    rwserve-brute-force {
        location `/srv/rwserve-plugins/node_modules/rwserve-brute-force/dist/index.js`
        config {
            max-visits      5
            grace-period    300
            blackout-period 900
            log-failures    true
        }
    }
    router {
        `/rbac/credentials/*`   *methods=POST      *plugin=rwserve-brute-force
    }    
}
</pre>

The `config` settings can be adjusted using this guidance.

`max-visits` is a positive integer. This is the number of requests to the target
resource allowed during the grace period before being blocked. A typical setting
might be 3 to 6, while an aggressive setting would be 1.

`grace-period` is an integer number of seconds specifying a window of time during
which requests are counted. The counter for each IP address is reset to zero
when this much time has elapsed since the first request. If the counter exceeds
the max-visits threshold, a blackout is begun.

`blackout-period` is an integer number of seconds specifying the window of time
during which all requests to the target resource, by the blacklisted IP, are
blocked. When this time period has elapsed, the IP address is removed from the
blacklist and subsequent requests are honored, starting with a new grace period.

`log-failures` is a switch that may be either <kbd>true</kbd> or <kbd>false
</kbd>. If true, each request by an IP address during a blackout period is recorded in
the web log. If false, blackouts are silently enforced without recording to the
web log.

The `router` section lists one or more target resources that will participate in
the brute force scheme. In the above example, all HTTP `POST` requests for
resource paths beginning with `/rbac/credentials` will participate.

#### Cookbook

A full configuration file with typical settings for a server running on
localhost port 7443, is included in this NPM module at `etc/brute-force-config`.
To use this configuration file, adjust these variables if they don't match your
server setup:

<pre>
$PLUGIN-PATH='/srv/rwserve-plugins/node_modules/rwserve-brute-force/dist/index.js'
$PRIVATE-KEY='/etc/pki/tls/private/localhost.key'
$CERTIFICATE='/etc/pki/tls/certs/localhost.crt'
$DOCUMENTS-PATH='/srv/rwserve/configuration-docs'
</pre>

### Usage

#### Server

Start the server using the configuration file just prepared. Use Bash to start
the server in the background, like this:

<pre>
[user@host ~]# rwserve /srv/rwserve-plugins/node_modules/rwserve-brute-force/etc/brute-force-config &
</pre>

#### Forcing a blackout

Use CURL to submit a sequence of POST requests to your sever. The first five
requests will return with `403 Forbidden` with a response header `rw-rbac-forbidden`
indicating that invalid credentials were provided. The sixth and subsequent
requests will return `403 Forbidden` without any supplemental header. Close
examination of the server's logged messages will reveal something like `error RwserveBruteForce RA=127.0.0.1; CT=6`
indicating the remote address (RA) and count (CT) for the blocked request.

<pre>
curl -X POST -d "action=login&user=root&password=toor" https://localhost:7443/rbac/credentials/login -H content-type:application/x-www-form-urlencoded -H content-length:36 -v
curl -X POST -d "action=login&user=admin&password=adm" https://localhost:7443/rbac/credentials/login -H content-type:application/x-www-form-urlencoded -H content-length:36 -v
curl -X POST -d "action=login&user=debug&password=dbg" https://localhost:7443/rbac/credentials/login -H content-type:application/x-www-form-urlencoded -H content-length:36 -v
curl -X POST -d "action=login&user=setup&password=123" https://localhost:7443/rbac/credentials/login -H content-type:application/x-www-form-urlencoded -H content-length:36 -v
curl -X POST -d "action=login&user=devops&password=me" https://localhost:7443/rbac/credentials/login -H content-type:application/x-www-form-urlencoded -H content-length:36 -v
</pre>

#### Deployment

Once you've tested the plugin and are ready to go live, adjust your production
web server's configuration in `/etc/rwserve/rwserve.conf` and restart it using `systemd`
. . .

<pre>
[user@host ~]# systemctl restart rwserve
</pre>

. . . then monitor its request/response activity with `journald`.

<pre>
[user@host ~]# journalctl -u rwserve -ef
</pre>

### Prerequisites

This is a plugin for the **Read Write Tools HTTP/2 Server**, which works on Linux
platforms.


<table>
	<tr><th>Software</th> <th>Minimum Version</th> <th>Most Recent Version</th></tr>
	<tr><td>Ubuntu</td> 		<td>16 Xenial Xerus</td> <td>16 Xenial Xerus</td></tr>
	<tr><td>Debian</td> 		<td>9 Stretch</td> 		<td>10 Buster</td></tr>
	<tr><td>openSUSE</td>	<td>openSUSE 15.1</td> 	<td>openSUSE 15.1</td></tr>
	<tr><td>Fedora</td> 		<td>Fedora 27</td> 		<td>Fedora 32</td></tr>
	<tr><td>CentOS</td>		<td>CentOS 7.4</td>		<td>CentOS 8.1</td></tr>
	<tr><td>RHEL</td> 		<td>RHEL 7.8</td>		<td>RHEL 8.2</td></tr>
	<tr><td>RWSERVE</td>		<td>RWSERVE 1.0.1</td>	<td>RWSERVE 1.0.47</td></tr>
	<tr><td>Node.js</td>		<td>Node.js 10.3</td>	<td>Node.js 12.17</td></tr>
</table>

### Review


<table>
	<tr><th>Lessons</th></tr>
	<tr><td>This plugin demonstrates these concepts: <ul><li>Passing configuration variables into the plugin.</li> <li>Using the <code>startup()</code> method for initialization. </li> <li>Accessing each request's IP address.</li> <li>Periodically triggering a cleanup operation.</li> </ul> Find other plugins for the <code>Read Write Tools HTTP/2 Server</code> using <a href='https://www.npmjs.com/search?q=keywords:rwserve'>npm</a> with these keywords: <kbd>rwserve</kbd>, <kbd>http2</kbd>, <kbd>plugins</kbd>. </td></tr>
</table>

### License

The <span>rwserve-brute-force</span> plugin is licensed under the
MIT License.

<img src='/img/blue-seal-mit.png' width=80 align=right />

<details>
	<summary>MIT License</summary>
	<p>Copyright © 2020 Read Write Tools.</p>
	<p>Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:</p>
	<p>The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.</p>
	<p>THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.</p>
</details>

### Availability


<table>
	<tr><td>Source code</td> 			<td><a href='https://github.com/readwritetools/rwserve-brute-force'>github</a></td></tr>
	<tr><td>Package installation</td> <td><a href='https://www.npmjs.com/package/rwserve-brute-force'>NPM</a></td></tr>
	<tr><td>Documentation</td> 		<td><a href='https://hub.readwritetools.com/plugins/brute-force.blue'>Read Write Hub</a></td></tr>
</table>

