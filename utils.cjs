const path = require('node:path');
const fs = require('node:fs');
const util = require('node:util');
const crypto = require('node:crypto');
const { promises: fsPromises } = require('fs');
const { Readable, pipeline } = require('stream');
const { validate } = require('uuid');
const sharp = require('sharp');
const axios = require('axios');

/**
 Retrieves filename and directory name from a file path.
 @param {string} filePath - The file path (e.g., __filename).
 @returns {Object} - An object containing filename and dirname properties.
 */
const __ = (filePath) => {
  const filename = filePath;
  const dirname = path.dirname(filename);

  return {
    filename,
    dirname
  };
};

/**
 Checks whether a variable is defined.
 @param {*} variable - The variable to check.
 @returns {boolean} - true if the variable is defined, otherwise false.
 */
const isDefined = (variable) => {
  return typeof variable !== 'undefined';
};

/**
 Checks whether a variable is null.
 @param {*} variable - The variable to check.
 @param {boolean} strict - Indicates whether to perform a strict comparison (default is true).
 @returns {boolean} - true if the variable is null, otherwise false.
 */
const isNull = (variable, strict = true) => {
  return strict
    ? variable === null
    : variable === null || variable === 0 || variable === '0';
};

/**
 Checks whether a variable is empty.
 @param {*} variable - The variable to check.
 @returns {boolean} - true if the variable is empty, otherwise false.
 */
const isEmpty = (variable) => {
  if (isNull(variable)) {
    return true;
  } else if (typeof variable === 'boolean') {
    return variable === false;
  } else if (typeof variable === 'number') {
    return variable === 0;
  } else if (typeof variable === 'string' || Array.isArray(variable)) {
    return variable.length === 0;
  } else if (typeof variable === 'object') {
    return objectToText(variable) === '{}';
  }
  return false;
};

/**
 Checks whether a variable has data.
 @param {*} variable - The variable to check.
 @returns {boolean} - true if the variable has data, otherwise false.
 */
const hasData = (variable) => {
  return isDefined(variable) && !isEmpty(variable);
};

/**
 Checks whether a variable is an object.
 @param {*} variable - The variable to check.
 @returns {boolean} - true if the variable is an object, otherwise false.
 */
const isObject = (variable) => {
  return typeof variable === 'object' &&
    !isNull(variable) &&
    !Array.isArray(variable);
};

/**
 Checks whether a variable is a string.
 @param {*} variable - The variable to check.
 @returns {boolean} - true if the variable is a string, otherwise false.
 */
const isString = (variable) => {
  return typeof variable === 'string';
};

/**
 Validates whether a given string is a properly formatted URL.
 @param {string} variable - The string to validate as a URL.
 @returns {boolean} - True if the string is a valid URL, false otherwise.
 */
const isURL = (variable) => {
  try {
    const url = new URL(variable);
    return url.hostname.includes('.');
  } catch (error) {
    return false;
  }
};

/**
 Checks whether a variable is a valid UUID.
 @param {string} variable - The variable to check.
 @returns {boolean} - true if the variable is a valid UUID, otherwise false.
 */
const isUUID = (variable) => {
  return validate(variable);
};

/**
 Checks if a given variable is an instance of Buffer.
 @param {any} variable - The variable to check.
 @returns {boolean} - True if the variable is a Buffer, false otherwise.
 */
const isBuffer = (variable) => {
  return variable instanceof Buffer;
};

/**
 Checks if a given string is a valid Base64 encoded string.
 @param {string} variable - The string to check.
 @returns {boolean} - True if the string is a valid Base64 string, false otherwise.
 */
const isBase64 = (variable) => {
  const base64Data = variable?.split('base64,')?.at(1) || variable;

  return base64Data &&
    base64Data.length % 4 === 0 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(base64Data);
};

/**
 Checks if the current runtime environment is a browser.
 @returns {boolean} - True if running in a browser environment, false otherwise.
 */
const isBrowser = () => {
  return typeof window !== 'undefined';
};

/**
 Gets the first element from an array, if available.
 @param {Array} array - The input array.
 @returns {*} - The first element of the array, or an empty array if the array is empty or undefined.
 */
const getFirst = (array) => {
  return array?.at();
};

/**
 Gets the last element from an array, if available.
 @param {Array} array - The input array.
 @returns {*} - The last element of the array, or undefined if the array is empty or undefined.
 */
const getLast = (array) => {
  return array?.at(-1);
};

/**
 Returns a random element from the given array.
 @param {Array} array - The input array.
 @returns {*} - A random element from the array.
 */
const getRandom = (array) => {
  const randomIndex = Math.floor(Math.random() * array.length);
  return array[randomIndex];
};

/**
 Returns an array containing only unique elements.
 @param {Array} array - The input array.
 @returns {Array} - An array with unique elements.
 */
const getUniqueArray = (array) => {
  return array.filter((item, index, self) => item && index === (
    isObject(item)
      ? self.findIndex(object => JSON.stringify(object) === JSON.stringify(item))
      : array.indexOf(item)
  ));
};

/**
 Ensures the input is returned as an array.
 @param {any} variable - The input to be transformed into an array.
 @returns {Array} - The input as an array if not already, or the input itself if it is an array.
 */
const ensureArray = (variable) => {
  return Array.isArray(variable) ? variable : [variable];
};

/**
 Creates a new object by excluding properties with falsy values (undefined, null, false, '', 0) from the input object.
 @param {Object} object - The input object.
 @returns {Object} - A new object containing only truthy properties of the input object.
 */
const getCleanObject = (object) => {
  return Object.keys(object).reduce((newObject, property) => {
    if (hasData(object[property])) {
      newObject[property] = object[property];
    }
    return newObject;
  }, {});
};

/**
 Creates a new object by excluding specified properties from the input object.
 @param {Object} object - The input object.
 @param {string[]} properties - An array of property names to be excluded from the new object.
 @returns {Object} - A new object containing all properties of the input object, except those listed in the 'properties' array.
 */
const getObjectWithoutProperties = (object, properties = []) => {
  return Object.keys(object).reduce((newObject, property) => {
    if (!properties.includes(property)) {
      newObject[property] = object[property];
    }
    return newObject;
  }, {});
};

/**
 Creates a new object with selected properties from the input object.
 @param {Object} object - The input object.
 @param {Array} properties - An array of property names to include in the new object (default is an empty array).
 @returns {Object} - A new object containing only the specified properties from the input object.
 */
const getObjectWithProperties = (object, properties = []) => {
  return Object.keys(object).reduce((newObject, property) => {
    if (properties.includes(property)) {
      newObject[property] = object[property];
    }
    return newObject;
  }, {});
};

/**
 Extracts specified properties from an array of objects.
 @param {Array} objects - The array of objects to extract properties from.
 @param {Array|string} properties - An array of property names or a single property name to extract (default is an empty array).
 @returns {Array} - An array containing objects with only the specified properties.
 */
const getObjectsProperties = (objects, properties) => {
  return objects.map(object => Array.isArray(properties)
    ? getObjectWithProperties(object, properties)
    : object[properties]
  );
};

/**
 Extracts specified properties from an object, returning them in a new object and removing them from the original object.
 @param {Object} object - The object from which properties are to be taken.
 @param {string[]|string} properties - The properties to extract.
 @returns {Object} - An object containing the extracted properties and their values.
 */
const takeObjectProperties = (object, properties) => {
  return ensureArray(properties).reduce((takenProperties, property) => {
    if (object[property]) {
      takenProperties[property] = object[property];
      delete object[property];
    }
    return takenProperties;
  }, {});
};

/**
 Extracts the 'id' property from an array of objects.
 @param {Array} objects - The array of objects to extract 'id' properties from.
 @returns {Array} - An array containing the 'id' properties of the input objects.
 */
const getObjectsIds = (objects) => {
  return getObjectsProperties(objects, 'id');
};

/**
 Extracts the domain from a given URL, optionally capitalizing the domain.
 Removes the 'www.' prefix and the top-level domain from the hostname.
 @param {string} url - The URL from which to extract the domain.
 @param {boolean} [isCapitalize=false] - Whether to capitalize the first letter of the domain.
 @returns {string} - The extracted and optionally capitalized domain name.
 */
const getDomain = (url, isCapitalize = false) => {
  const parsedUrl = new URL(url);
  const hostname = parsedUrl.hostname;
  const parts = hostname.replace('www.', '').split('.');
  const domain = parts.slice(0, -1).join('.');
  return isCapitalize ? capitalize(domain) : domain;
};

/**
 Capitalizes the first letter of a given string.
 @param {string} string - The string to modify.
 @returns {string} - The string with the first letter capitalized.
 */
const capitalize = (string) => {
  return string.charAt(0).toUpperCase() + string.slice(1);
};

/**
 Converts an object into a string representation, handling different environments.
 In non-browser environments, uses Node.js's util.inspect for formatting.
 In browser environments, manually stringifies the object, supporting circular references and limiting depth.
 Arrays and objects are processed recursively to a specified depth to avoid infinite loops.
 @param {Object|Array} object - The object or array to stringify.
 @param {number} depth - The maximum depth to traverse in the object, default is 5.
 @returns {string} - A string representation of the object or array.
 */
const objectToText = (object, depth = 5) => {
  if (!isBrowser()) {
    return util.inspect(object, { depth: depth });
  }

  const seen = new WeakSet();

  const stringify = (obj, currentDepth) => {
    if (currentDepth > depth) {
      return '...';
    }
    if (typeof obj !== 'object' || obj === null) {
      return JSON.stringify(obj);
    }
    if (seen.has(obj)) {
      return '[Circular]';
    }

    seen.add(obj);

    const isArray = Array.isArray(obj);
    const data = isArray ? obj : Object.keys(obj);

    const result = data.map(key => {
      const value = isArray ? key : obj[key];
      return (
        isArray ? '' : `"${key}": `
      ) + stringify(value, currentDepth + 1);
    });

    seen.delete(obj);

    return (isArray ? '[' : '{') + result.join(', ') + (isArray ? ']' : '}');
  };

  return stringify(object, 0);
};

/**
 Converts a text string into an array of words.
 Removes extra spaces and line breaks. In strict mode, trims unwanted characters from words.
 @param {string} text - The input text.
 @param {boolean} [strict=true] - Whether to trim extra characters from words.
 @returns {string[]} - An array of words.
 */
const textToWords = (text, strict = true) => {
  return isString(text)
    ? text.replace(/(\n)/g, ' ')
      .replace(/(\s\s)/g, ' ')
      .split(' ')
      .map(word => strict ? trimChars(word) : word)
      .filter(Boolean)
    : [];
};

/**
 Trims specified characters from the start and end of a string.
 @param {string} string - The input string to trim.
 @param {string[]} [chars] - An array of characters to remove (defaults to common punctuation and whitespace).
 @returns {string} - The trimmed string.
 */
const trimChars = (string, chars) => {
  chars = chars || [
    '.', ',', ':', ';', '?', '!', '\'', '"', '`', '*', '(', ')', '[', ']',
    '{', '}', '<', '>', '/', '|', '\\', '-', '—', '_', '=', ' '
  ];

  const escapedChars = chars
    .map(char => char.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'))
    .join('');

  return string.replace(new RegExp(`^[${escapedChars}]+|[${escapedChars}]+$`, 'g'), '');
};

/**
 Computes the SHA-256 hash of a given string and returns it in hexadecimal format.
 @param {string} string - The input string to hash.
 @returns {string} - The SHA-256 hash of the input string in hexadecimal format.
 */
const sha256 = (string) => {
  return crypto.createHash('sha256').update(string).digest('hex');
};

/**
 * Generates a 256-bit (32-byte) cryptographic key from a password using SHA-256 hash.
 * @param {string} password - The input password or passphrase.
 * @returns {Buffer} - A 32-byte cryptographic key derived from the password.
 */
const getKey = (password) => {
  return crypto.createHash('sha256').update(password).digest();
};

/**
 * Encrypts a UTF-8 string using AES-256-CBC with a password-derived key.
 * @param {string} text - The plaintext to encrypt.
 * @param {string} password - The password used to derive the encryption key.
 * @returns {string} - A string containing the IV and encrypted data, separated by a colon (IV:encrypted).
 */
const encrypt = (text, password) => {
  const iv = crypto.randomBytes(16);
  const key = getKey(password);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(text, 'utf8'),
    cipher.final()
  ]);

  return iv.toString('hex') + ':' + encrypted.toString('hex');
};

/**
 * Decrypts AES-256-CBC encrypted data using a password-derived key.
 * @param {string} encryptedData - The encrypted string in the format "iv:encrypted", both in hex.
 * @param {string} password - The password used to derive the decryption key.
 * @returns {string} - The decrypted UTF-8 string.
 */
const decrypt = (encryptedData, password) => {
  const [ivHex, encryptedHex] = encryptedData.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const key = getKey(password);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return decrypted.toString('utf8');
};

/**
 * Encrypts a UTF-8 text string using XOR cipher with the given keyword.
 * @param {string} text - The plaintext to encrypt.
 * @param {string} keyword - The keyword used for XOR encryption.
 * @returns {string} - The Base64-encoded encrypted string.
 */
const xorEncrypt = (text, keyword) => {
  const buffer = Buffer.from(text, 'utf-8');
  const key = Buffer.from(keyword, 'utf-8');
  const result = Buffer.alloc(buffer.length);

  for (let i = 0; i < buffer.length; i++) {
    result[i] = buffer[i] ^ key[i % key.length];
  }

  return result.toString('base64');
};

/**
 * Decrypts a Base64-encoded string using XOR cipher with the given keyword.
 * @param {string} encoded - The Base64-encoded string to decrypt.
 * @param {string} keyword - The keyword used for XOR decryption (must match the encryption keyword).
 * @returns {string} - The decrypted UTF-8 string.
 */
const xorDecrypt = (encoded, keyword) => {
  const buffer = Buffer.from(encoded, 'base64');
  const key = Buffer.from(keyword, 'utf-8');
  const result = Buffer.alloc(buffer.length);

  for (let i = 0; i < buffer.length; i++) {
    result[i] = buffer[i] ^ key[i % key.length];
  }

  return result.toString('utf-8');
};

/**
 Delays execution for a specified duration in seconds and resolves to true when complete.
 @param {number} duration - The duration to wait in seconds.
 @returns {Promise<boolean>} - A promise that resolves to true after the specified duration.
 */
const sleep = (duration) => {
  return new Promise(resolve =>
    setTimeout(() => resolve(true), duration * 1000)
  );
};

/**
 * Downloads a file from the specified URL and saves it to the given file path.
 * @param {string} url - The URL of the file to download.
 * @param {string} filePath - The local file path where the downloaded file will be saved.
 * @returns {Promise<void>} - A promise that resolves when the download is complete.
 */
const downloadFile = async (url, filePath) => {
  try {
    const response = await axios.get(url, { responseType: 'stream' });

    const streamPipeline = util.promisify(pipeline);
    await streamPipeline(response.data, fs.createWriteStream(filePath));
  } catch (error) {
    logger(error, 'downloadFile()', { url, filePath });
  }
};

/**
 * Downloads a file from the specified URL and returns its content as a buffer.
 * @param {string} url - The URL of the file to download.
 * @returns {Promise<Buffer>} - A promise that resolves to the file's buffer.
 */
const downloadFileBuffer = async (url) => {
  const response = await axios.get(url, {
    responseType: 'arraybuffer'
  })

  return Buffer.from(response.data)
}

/**
 * Writes a buffer to a file at the specified path using a stream.
 * @param {Buffer} buffer - The buffer to write to the file.
 * @param {string} filePath - The destination file path.
 * @returns {Promise<void>} - A promise that resolves when the file has been written.
 */
const bufferToFile = async (buffer, filePath) => {
  const stream = bufferToStream(buffer)
  await streamToFile(stream, filePath)
}

/**
 Converts a buffer into a stream based on the environment.
 In non-browser environments, it returns a Readable stream that emits the buffer content.
 In browser environments, it converts the buffer to a Blob and returns its stream.
 @param {Buffer|Uint8Array} buffer - The buffer to be converted into a stream.
 @returns {ReadableStream|BlobStream} - A stream that emits the buffer's content.
 */
const bufferToStream = (buffer) => {
  return !isBrowser()
    ? new Readable({
      read() {
        this.push(buffer);
        this.push(null);
      }
    })
    : new Blob([buffer]).stream();
};

/**
 Writes data from a stream to a file asynchronously.
 @param {ReadableStream} stream - The stream source to write from.
 @param {string} filePath - The file path where the stream data will be written.
 @returns {Promise} - Resolves on successful write completion, rejects on error.
 */
const streamToFile = async (stream, filePath) => {
  return new Promise((resolve, reject) => {
    const writer = fs.createWriteStream(filePath);
    stream.pipe(writer);
    writer.on('finish', resolve);
    writer.on('error', reject);
  });
};

/**
 Extracts the Base64 part from a data URL or returns the original URL if no Base64 segment is found.
 @param {string} url - The data URL containing the Base64 segment.
 @returns {string} - The extracted Base64 string or the original URL if no Base64 is present.
 */
const urlToBase64 = (url) => {
  return url.split('base64,').at(1) || url;
};

/**
 Converts a file object to a Base64-encoded string asynchronously, optionally including the data URL prefix.
 @param {File} file - The file object to convert.
 @param {boolean} [url=false] - Whether to include the full data URL prefix in the result.
 @returns {Promise<string>} - A promise that resolves with the Base64-encoded string or the full data URL if specified, or rejects with an error.
 */
const fileToBase64 = async (file, url = false) => {
  try {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsDataURL(file);
      reader.onload = () => resolve(
        url
          ? reader.result
          : reader.result.split('base64,').at(1)
      );
      reader.onerror = error => reject(error);
    });
  } catch (error) {
    logger(error, 'fileToBase64', { file, url });
  }
};

/**
 Converts a Base64-encoded string to a binary format.
 In non-browser environments, returns a Buffer; in browsers, converts to Uint8Array.
 @param {string} base64 - The Base64 string to convert.
 @returns {Buffer|Uint8Array} - The binary representation of the Base64 string, either as Buffer or Uint8Array.
 */
const base64ToFile = (base64) => {
  try {
    if (!isBrowser()) {
      return Buffer.from(base64, 'base64');
    }

    const binaryString = atob(base64);
    const length = binaryString.length;
    const bytes = new Uint8Array(new ArrayBuffer(length));

    for (let i = 0; i < length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
  } catch (error) {
    logger(error, 'base64ToFile', { base64 });
  }
};

/**
 Asynchronously writes data to a file only if the environment is not a browser.
 First checks if the operation is in a browser and if so, returns false.
 If not, it creates necessary directories and writes the data to the specified file path.
 Catches and logs any errors encountered during the file operations.
 @param {string} filePath - Path where the data will be written.
 @param {any} data - Content to write to the file.
 @param {Object} options - Write options, defaults to appending if the file exists.
 @returns {Promise<boolean>} - Resolves with true on successful write, false otherwise.
 */
const writeFile = async (filePath, data, options = { flag: 'a+' }) => {
  if (isBrowser()) {
    return false;
  }

  try {
    const directoryPath = filePath.substring(0, filePath.lastIndexOf('/'));
    await fsPromises.mkdir(directoryPath, { recursive: true });
    await fsPromises.writeFile(filePath, data, options);
    return true;
  } catch (error) {
    logger(error, 'writeFile', { filePath, data, options }, false);
    return false;
  }
};

/**
 Custom logging function that captures and formats log entries based on type (error or general).
 Logs are timestamped and can include function-specific messages or general data arrays.
 Errors and data can optionally be logged to a file in non-browser environments.
 @param {...any} args - Includes log content, function name, additional data, and file logging flag.
 */
const logger = (...args) => {
  const [log, functionName, functionData, logFile] = args;
  const logType = log instanceof Error ? 'error' : 'log';
  let logMessage = `# ${new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Bangkok' })} — `;

  if (logType === 'error') {
    logMessage += isDefined(functionName)
      ? `Error while ${functionName}: `
      : `${log.name}: `;
    logMessage += `${log.message}\n`;
  } else {
    logMessage += isDefined(functionName)
      ? `Logging while ${functionName}: `
      : ``;
    logMessage += Array.isArray(log)
      ? `${log.map(item => isObject(item) ? objectToText(item) : item).join('\n')}\n`
      : `${log}\n`;
  }

  if (hasData(functionData)) {
    logMessage += `${objectToText(functionData, functionData?.depth)}\n`;
  }

  console[logType](logMessage);

  if (!isBrowser() && logFile !== false) {
    const logDate = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const logPath = `/${process.cwd()}/logs/${logDate}.${logType}`;

    writeFile(logPath, `${logMessage}\n`)
      .catch(error => logger(error, 'logger', args, false));
  }
};

/**
 Attempts to retrieve a value from a cache or generates it using a callback if expired or not present.
 Validates cache freshness using the expiry rule before serving cached data.
 If data is not in cache or is expired, it recalculates, caches, and then returns the new value.
 Errors during operation are caught and logged.
 @param {Object} cache - The cache storage object.
 @param {string} key - The cache key to look up or store the data under.
 @param {Function} callback - Function to compute the value if necessary.
 @param {string} [expiry='+1year'] - String indicating how long the cache value is considered fresh.
 @returns {Promise<any>} - The value from the cache or newly computed.
 */
const getCache = async (cache, key, callback, expiry = '+1year') => {
  try {
    if (cache.has(key)) {
      const { cacheValue, cacheDate } = cache.get(key);
      if (checkCacheDate(cacheDate, expiry)) {
        return cacheValue;
      }
    }

    const cacheValue = await callback();
    const cacheDate = Date.now();
    cache.set(key, { cacheValue, cacheDate });
    return cacheValue;
  } catch (error) {
    logger(error, 'getCache', { cache, key, callback, expiry });
  }
};

/**
 Checks if the cache contains a valid entry for a given key based on a specified expiry.
 @param {Object} cache - The cache storage object.
 @param {string} key - The key to check in the cache.
 @param {string} [expiry='+1year'] - The duration for which the cache entry is considered valid.
 @returns {boolean} - True if a valid cache entry exists, false otherwise.
 */
const hasCache = (cache, key, expiry = '+1year') => {
  return cache.has(key) && checkCacheDate(cache.get(key)?.cacheDate, expiry);
};

/**
 Clears expired entries from the cache based on a specified expiry rule.
 @param {Object} cache - The cache storage object to be cleaned.
 @param {string} [expiry='+1year'] - The duration after which cache entries are considered expired.
 @returns {Object} - The updated cache object after removal of expired entries.
 */
const clearCache = (cache, expiry = '+1year') => {
  cache.forEach((item, key) => {
    if (checkCacheDate(item?.cacheDate, expiry)) return;
    cache.delete(key);
  });
  return cache;
};

/**
 Determines if a cached date is still within its specified expiry period.
 @param {number} cacheDate - The timestamp of the cached entry to check.
 @param {string} [expiry='+1year'] - The relative time string that specifies how long after the cacheDate the entry expires.
 @returns {boolean} - True if the current date is before the expiry date, false otherwise.
 */
const checkCacheDate = (cacheDate, expiry = '+1year') => {
  return Date.now() < getModifiedDate(`+${expiry}`, cacheDate);
};

/**
 Adjusts a given initial date by a specified amount of time defined in a string input.
 The input specifies the direction (positive or negative) and magnitude in years, months, etc.
 If no valid input is found, returns the current timestamp.
 @param {string} input - Modification instruction, e.g., "+1 year", "-2 hours".
 @param {number} [initialDate=Date.now()] - The starting timestamp to modify.
 @returns {number} - The modified date as a timestamp.
 */
const getModifiedDate = (input, initialDate = null) => {
  const regex = /(\+|-)\s*(\d+)\s*(year|month|week|day|hour|min|second)s?/i;
  const match = input.match(regex);

  if (match) {
    const [_, sign, amount, unit] = match;
    const date = new Date(initialDate ?? Date.now());
    const value = parseInt(amount, 10) * (sign === '+' ? 1 : -1);

    switch (unit.toLowerCase()) {
      case 'year':
        date.setFullYear(date.getFullYear() + value);
        break;
      case 'month':
        date.setMonth(date.getMonth() + value);
        break;
      case 'week':
        date.setDate(date.getDate() + value * 7);
        break;
      case 'day':
        date.setDate(date.getDate() + value);
        break;
      case 'hour':
        date.setHours(date.getHours() + value);
        break;
      case 'min':
        date.setMinutes(date.getMinutes() + value);
        break;
      case 'second':
        date.setSeconds(date.getSeconds() + value);
        break;
      default:
        break;
    }

    return date.getTime();
  }

  return new Date().getTime();
};

/**
 Clears the current text selection in the browser window.
 If not running in a browser environment, the function does nothing.
 */
const clearSelection = () => {
  if (!isBrowser()) {
    return false;
  }

  const selection = window.getSelection();
  if (selection) {
    selection.removeAllRanges();
  }
};

/**
 Creates a thumbnail from a given file, which can be a Buffer, a Base64 string, or a data URL.
 It resizes the image if a resize dimension is provided and sets the image quality.
 @param {Buffer|string} file - The file or URL to be processed.
 @param {number|boolean} resize - The dimensions to resize the image to, or false to skip resizing.
 @param {number} [quality=100] - The quality of the output JPEG image.
 @returns {Promise<Buffer>} - A promise that resolves with the thumbnail as a buffer, or logs an error if unsuccessful.
 */
const getThumbnail = async (file, resize, quality = 100) => {
  try {
    const fileBuffer = isBuffer(file)
      ? file
      : isBase64(file)
        ? Buffer.from(urlToBase64(file), 'base64')
        : null;

    if (isNull(fileBuffer)) {
      throw new Error('Invalid file buffer');
    }

    let image = sharp(fileBuffer);
    if (resize) {
      image = image.resize(resize);
    }

    return await image.jpeg({ quality }).toBuffer();
  } catch (error) {
    logger(error, 'getThumbnail', { file, resize, quality });
  }
};

/**
 Generates a specific error message based on a given type and an optional insert parameter.
 @param {string} type - The error type identifier.
 @param {string|null} [insert=null] - Optional string to insert into the message for dynamic content.
 @returns {string} - The generated error message.
 */
const getErrorMessage = (type, insert = null) => {
  switch (type) {
    case '!method':
      return `The ${insert} method was not found.`;
    case '!service':
      return `The ${insert} service was not found.`;
    case '!model':
      return 'Model was not found.';
    case '!object':
      return `The object(s) is/are empty.`;
    case 'object!array':
      return `The object(s) is/are not an Array.`;
    case 'object!object':
      return `The object(s) is/are not an Object.`;
    case '!objectName':
      return `The name(s) of the object(s) is/are empty.`;
    case '!argument':
      return `The ${insert} argument(s) is/are empty.`;
    case 'argument!string':
      return `The ${insert} argument(s) is/are not an String.`;
    case 'argument!integer':
      return `The ${insert} argument(s) is/are not an Integer.`;
    case 'argument!array':
      return `The ${insert} argument(s) is/are not an Array.`;
    case 'argument!object':
      return `The ${insert} argument(s) is/are not an Object.`;
    case 'argument!uuid':
      return `The ${insert} argument(s) is/are not an UUID.`;
    case '!created':
      return `The objects were not created.`;
    case '!updated':
      return `The objects were not updated.`;
    case '!deleted':
      return `The objects were not deleted.`;
    case '!added':
      return `The objects associations were not added.`;
    default:
      return type;
  }
};

/**
 Executes a callback function and optionally repeats it after a set time interval.
 Retries up to 10 times if an error occurs, with increasing delay between attempts.
 @param {Function} callback - The function to execute and possibly repeat.
 @param {number|null} [repeatTime=null] - Time in seconds to wait before repeating the callback, or null to run only once.
 @param {number} [attempt=0] - The current retry attempt count.
 @returns {Promise<any>} - The result of the callback or false after exceeding retry limits.
 */
const run = async (callback, repeatTime = null, attempt = 1) => {
  try {
    return isNull(repeatTime)
      ? await callback()
      : await callback() && await sleep(repeatTime) && await run(callback, repeatTime);
  } catch (error) {
    logger(error, `run, attempt ${attempt}`);
    return ++attempt <= 10
      ? await sleep(attempt * 10) && await run(callback, repeatTime, attempt)
      : false;
  }
};

module.exports = {
  __,
  isDefined,
  isNull,
  isEmpty,
  hasData,
  isObject,
  isString,
  isURL,
  isUUID,
  isBuffer,
  isBase64,
  isBrowser,
  getFirst,
  getLast,
  getRandom,
  getUniqueArray,
  ensureArray,
  getCleanObject,
  getObjectWithoutProperties,
  getObjectWithProperties,
  getObjectsProperties,
  takeObjectProperties,
  getObjectsIds,
  getDomain,
  capitalize,
  objectToText,
  textToWords,
  trimChars,
  sha256,
  getKey,
  encrypt,
  decrypt,
  xorEncrypt,
  xorDecrypt,
  sleep,
  downloadFile,
  downloadFileBuffer,
  bufferToFile,
  bufferToStream,
  streamToFile,
  urlToBase64,
  fileToBase64,
  base64ToFile,
  writeFile,
  logger,
  getCache,
  hasCache,
  clearCache,
  checkCacheDate,
  getModifiedDate,
  clearSelection,
  getThumbnail,
  getErrorMessage,
  run
};