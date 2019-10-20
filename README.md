 [![CC0](http://i.creativecommons.org/p/zero/1.0/88x31.png)](http://creativecommons.org/publicdomain/zero/1.0/)   
To the extent possible under law, [1000TurquoisePogs](https://github.com/1000TurquoisePogs/silly-file-server) has waived all copyright and related or neighboring rights to this repository of silly-file-server. This work is published from: United States.


Getting Started Instructions:
1. Clone
1. Run node file-server.js

Restricting access:
1. Make a passwords.json file in the root directory
1. Add the name of a file or directory within the JSON
1. Add a string as a password
It could look like:

```json
{
  "98": "123",
  "95-tan.jpg": "4567"
}
```
Which would allow access to a file/folder called 98, and a file/folder called 95-tan.jpg under the circumstance someone accessed the URLs with the ?pass query parameter.
The set of passwords the server uses is determined by reading this file every 5 minutes, so adding or removing takes 5 minutes.

Accessing restricted URLs:
Use the query parameter ?pass=PASSWORD with whatever PASSWORD was given to you by the owner.

Archives:
If you use the query parameter ?zip=1, the requested file or folder will be sent as a zip.
The zip is written to disk in an area that will expire within 1 hour.

Expiration:
TODO
