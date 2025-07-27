# Node.js Utility Library

A lightweight and versatile utility library for Node.js and browser environments, providing a collection of helper functions for common tasks like type checking, file handling, caching, string manipulation, and more. This package is designed to simplify development with reusable, well-documented functions.

## Installation

Install the package via npm:

```bash
npm install favie-utils
```

## Usage

Import the library in your project:

```javascript
import * as utils from 'favie-utils';
```

Or import specific functions:

```javascript
import { isDefined, isEmpty, getThumbnail } from 'favie-utils';
```

## Features

### General Utilities
- `__`: Retrieves the filename and directory name from a URL or `import.meta.url`.
- `isDefined`: Checks if a variable is defined.
- `isNull`: Checks if a variable is null (strict or loose comparison).
- `isEmpty`: Checks if a variable is empty (supports strings, arrays, objects, etc.).
- `hasData`: Verifies if a variable is defined and non-empty.
- `isObject`: Checks if a variable is an object (excluding arrays and null).
- `isString`: Checks if a variable is a string.
- `isURL`: Validates if a string is a properly formatted URL.
- `isUUID`: Validates if a string is a valid UUID.
- `isBuffer`: Checks if a variable is a Buffer.
- `isBase64`: Verifies if a string is a valid Base64-encoded string.
- `isBrowser`: Detects if the runtime environment is a browser.

### Array Utilities
- `getFirst`: Returns the first element of an array.
- `getLast`: Returns the last element of an array.
- `getRandom`: Returns a random element from an array.
- `getUniqueArray`: Returns an array with unique elements.
- `ensureArray`: Ensures the input is returned as an array.

### Object Utilities
- `getCleanObject`: Creates a new object excluding falsy properties.
- `getObjectWithoutProperties`: Creates a new object excluding specified properties.
- `getObjectWithProperties`: Creates a new object with only specified properties.
- `getObjectsProperties`: Extracts specified properties from an array of objects.
- `takeObjectProperties`: Extracts and removes specified properties from an object.
- `getObjectsIds`: Extracts the `id` property from an array of objects.

### String and URL Utilities
- `getDomain`: Extracts the domain from a URL, with optional capitalization.
- `capitalize`: Capitalizes the first letter of a string.
- `objectToText`: Converts an object to a string representation, handling circular references.
- `textToWords`: Converts text to an array of words, with optional strict trimming.
- `trimChars`: Trims specified characters from the start and end of a string.
- `sha256`: Computes the SHA-256 hash of a string.

### File and Stream Handling
- `downloadFile`: Downloads a file from the specified URL and saves it to the given file path.
- `downloadFileBuffer`: Downloads a file from a URL and returns it as a buffer.
- `bufferToFile`: Writes a buffer to a file using a stream.
- `bufferToStream`: Converts a buffer to a stream (Node.js or browser).
- `streamToFile`: Writes data from a stream to a file (Node.js only).
- `fileToBase64`: Converts a file to a Base64-encoded string (browser only).
- `base64ToFile`: Converts a Base64 string to a Buffer (Node.js) or Uint8Array (browser).
- `writeFile`: Writes data to a file, creating directories if needed (Node.js only).
- `getThumbnail`: Generates a thumbnail from a file (Buffer or Base64).

### Asynchronous and Caching Utilities
- `sleep`: Delays execution for a specified duration.
- `getCache`: Retrieves or generates cached data with expiry support.
- `hasCache`: Checks if a cache entry is valid.
- `clearCache`: Removes expired cache entries.
- `checkCacheDate`: Validates cache freshness based on expiry.
- `getModifiedDate`: Modifies a date based on a time string (e.g., `+1year`).
- `run`: Executes a callback with optional retry and repeat functionality.

### Browser-Specific Utilities
- `clearSelection`: Clears the current text selection in the browser.

### Error Handling
- `logger`: Custom logging function for errors and general logs, with file logging support (Node.js only).
- `getErrorMessage`: Generates specific error messages based on type.

## Examples

### Type Checking
```javascript
console.log(utils.isDefined(myVar)); // true if myVar is defined
console.log(utils.isEmpty([])); // true
console.log(utils.isURL('https://example.com')); // true
```

### Array Manipulation
```javascript
const arr = [1, 2, 3, 2];
console.log(utils.getUniqueArray(arr)); // [1, 2, 3]
console.log(utils.getRandom(arr)); // e.g., 2
```

### Object Manipulation
```javascript
const obj = { a: 1, b: null, c: 3 };
console.log(utils.getCleanObject(obj)); // { a: 1, c: 3 }
console.log(utils.getObjectWithProperties(obj, ['a'])); // { a: 1 }
```

### File Handling
```javascript
// Generate a thumbnail
const buffer = await utils.getThumbnail('data:image/jpeg;base64,...', 100, 80);
```

### Caching
```javascript
const cache = new Map();
const result = await utils.getCache(cache, 'key', async () => 'value', '+1day');
console.log(result); // 'value'
```

## Dependencies
- `node` (built-in): For path, fs, util, and crypto utilities.
- `uuid`: For UUID validation.
- `sharp`: For image processing (thumbnail generation).
- `axios`: For file downloading.

## Requirements
- Node.js >= 14.x
- Browser support for modern JavaScript (ES Modules)

## License
MIT License

## Contributing
Contributions are welcome! Please submit a pull request or open an issue on the [GitHub repository](https://github.com/faviebot/favie-utils#readme).

## Author
MxVY - <dev@mxvy.pw>

## Issues
Report bugs or suggest features on the [GitHub Issues page](https://github.com/faviebot/favie-utils/issues).