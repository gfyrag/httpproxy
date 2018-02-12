# httpproxy

TODO:
* Implements in memory caching of response with differents strategy : 
  * LRU
  * Small files only
* Smart request duplicate detection (No need to fetch to same resource multiple times)
* Http stats handler.
* Specific config by path/host.
* Improve logging.
* Test streamed requests
* Errors on remote conn closed