declare module 'favie-utils' {
  import { Readable } from 'stream';
  import { File } from 'buffer';

  /**
   * Retrieves filename and directory name from a URL or import.meta.url.
   * @param url - The URL or import.meta.url.
   * @returns An object containing filename and dirname properties.
   */
  export function __(url: string): { filename: string; dirname: string };

  /**
   * Checks whether a variable is defined.
   * @param variable - The variable to check.
   * @returns True if the variable is defined, otherwise false.
   */
  export function isDefined<T>(variable: T): variable is Exclude<T, undefined>;

  /**
   * Checks whether a variable is null.
   * @param variable - The variable to check.
   * @param strict - Indicates whether to perform a strict comparison (default is true).
   */
  export function isNull(variable: unknown): variable is null;

  /**
   * Checks whether a variable is empty.
   * @param variable - The variable to check.
   * @returns True if the variable is empty, otherwise false.
   */
  export function isEmpty(variable: unknown): boolean;

  /**
   * Checks whether a variable has data.
   * @param variable - The variable to check.
   * @returns True if the variable has data, otherwise false.
   */
  export function hasData(variable: unknown): boolean;

  /**
   * Checks whether a variable is an object.
   * @param variable - The variable to check.
   * @returns True if the variable is an object, otherwise false.
   */
  export function isObject(variable: unknown): variable is Record<string, unknown>;

  /**
   * Checks whether a variable is a string.
   * @param variable - The variable to check.
   * @returns True if the variable is a string, otherwise false.
   */
  export function isString(variable: unknown): variable is string;

  /**
   * Validates whether a given string is a properly formatted URL.
   * @param variable - The string to validate as a URL.
   * @returns True if the string is a valid URL, false otherwise.
   */
  export function isURL(variable: string): boolean;

  /**
   * Checks whether a variable is a valid UUID.
   * @param variable - The variable to check.
   * @returns True if the variable is a valid UUID, otherwise false.
   */
  export function isUUID(variable: string): boolean;

  /**
   * Checks if a given variable is an instance of Buffer.
   * @param variable - The variable to check.
   * @returns True if the variable is a Buffer, false otherwise.
   */
  export function isBuffer(variable: unknown): variable is Buffer;

  /**
   * Checks if a given string is a valid Base64 encoded string.
   * @param variable - The string to check.
   * @returns True if the string is a valid Base64 string, false otherwise.
   */
  export function isBase64(variable: string): boolean;

  /**
   * Checks if the current runtime environment is a browser.
   * @returns True if running in a browser environment, false otherwise.
   */
  export function isBrowser(): boolean;

  /**
   * Gets the first element from an array, if available.
   * @param array - The input array.
   * @returns The first element of the array, or undefined if the array is empty or undefined.
   */
  export function getFirst<T>(array?: T[]): T | undefined;

  /**
   * Gets the last element from an array, if available.
   * @param array - The input array.
   * @returns The last element of the array, or undefined if the array is empty or undefined.
   */
  export function getLast<T>(array?: T[]): T | undefined;

  /**
   * Returns a random element from the given array.
   * @param array - The input array.
   * @returns A random element from the array.
   */
  export function getRandom<T>(array: T[]): T;

  /**
   * Returns an array containing only unique elements.
   * @param array - The input array.
   * @returns An array with unique elements.
   */
  export function getUniqueArray<T>(array: T[]): T[];

  /**
   * Ensures the input is returned as an array.
   * @param variable - The input to be transformed into an array.
   * @returns The input as an array if not already, or the input itself if it is an array.
   */
  export function ensureArray<T>(variable: T | T[]): T[];

  /**
   * Creates a new object by excluding properties with falsy values.
   * @param object - The input object.
   * @returns A new object containing only truthy properties of the input object.
   */
  export function getCleanObject<T extends Record<string, any>>(object: T): Partial<T>;

  /**
   * Creates a new object by excluding specified properties from the input object.
   * @param object - The input object.
   * @param properties - An array of property names to be excluded from the new object.
   * @returns A new object containing all properties of the input object, except those listed in the 'properties' array.
   */
  export function getObjectWithoutProperties<T extends Record<string, any>>(
    object: T,
    properties?: string[]
  ): Partial<T>;

  /**
   * Creates a new object with selected properties from the input object.
   * @param object - The input object.
   * @param properties - An array of property names to include in the new object.
   * @returns A new object containing only the specified properties from the input object.
   */
  export function getObjectWithProperties<T extends Record<string, any>>(
    object: T,
    properties?: string[]
  ): Partial<T>;

  /**
   * Extracts specified properties from an array of objects.
   * @param objects - The array of objects to extract properties from.
   * @param properties - An array of property names or a single property name to extract.
   * @returns An array containing objects with only the specified properties.
   */
  export function getObjectsProperties<T extends Record<string, any>, K extends keyof T>(
    objects: T[],
    properties: K[] | K
  ): Array<Partial<T> | T[K]>;

  /**
   * Extracts specified properties from an object, returning them in a new object and removing them from the original object.
   * @param object - The object from which properties are to be taken.
   * @param properties - The properties to extract.
   * @returns An object containing the extracted properties and their values.
   */
  export function takeObjectProperties<T extends Record<string, any>>(
    object: T,
    properties: string | string[]
  ): Partial<T>;

  /**
   * Extracts the 'id' property from an array of objects.
   * @param objects - The array of objects to extract 'id' properties from.
   * @returns An array containing the 'id' properties of the input objects.
   */
  export function getObjectsIds<T extends { id: any }>(objects: T[]): any[];

  /**
   * Extracts the domain from a given URL, optionally capitalizing the domain.
   * @param url - The URL from which to extract the domain.
   * @param isCapitalize - Whether to capitalize the first letter of the domain.
   * @returns The extracted and optionally capitalized domain name.
   */
  export function getDomain(url: string, isCapitalize?: boolean): string;

  /**
   * Capitalizes the first letter of a given string.
   * @param string - The string to modify.
   * @returns The string with the first letter capitalized.
   */
  export function capitalize(string: string): string;

  /**
   * Converts an object into a string representation, handling different environments.
   * @param object - The object or array to stringify.
   * @param depth - The maximum depth to traverse in the object.
   * @returns A string representation of the object or array.
   */
  export function objectToText<T>(object: T, depth?: number): string;

  /**
   * Converts a text string into an array of words.
   * @param text - The input text.
   * @param strict - Whether to trim extra characters from words.
   * @returns An array of words.
   */
  export function textToWords(text: string, strict?: boolean): string[];

  /**
   * Trims specified characters from the start and end of a string.
   * @param string - The input string to trim.
   * @param chars - An array of characters to remove.
   * @returns The trimmed string.
   */
  export function trimChars(string: string, chars?: string[]): string;

  /**
   * Computes the SHA-256 hash of a given string and returns it in hexadecimal format.
   * @param string - The input string to hash.
   * @returns The SHA-256 hash of the input string in hexadecimal format.
   */
  export function sha256(string: string): string;

  /**
   * Generates a 256-bit (32-byte) cryptographic key from a password using SHA-256 hash.
   * @param {string} password - The input password or passphrase.
   * @returns {Buffer} - A 32-byte cryptographic key derived from the password.
   */
  export function getKey(password: string): Buffer;

  /**
   * Encrypts a UTF-8 string using AES-256-CBC with a password-derived key.
   * @param {string} text - The plaintext to encrypt.
   * @param {string} password - The password used to derive the encryption key.
   * @returns {string} - A string containing the IV and encrypted data, separated by a colon (IV:encrypted).
   */
  export function encrypt(text: string, password: string): string;

  /**
   * Decrypts AES-256-CBC encrypted data using a password-derived key.
   * @param {string} encryptedData - The encrypted string in the format "iv:encrypted", both in hex.
   * @param {string} password - The password used to derive the decryption key.
   * @returns {string} - The decrypted UTF-8 string.
   */
  export function decrypt(encryptedData: string, password: string): string;

  /**
   * Encrypts a UTF-8 text string using XOR cipher with the given keyword.
   * @param {string} text - The plaintext to encrypt.
   * @param {string} keyword - The keyword used for XOR encryption.
   * @returns {string} - The Base64-encoded encrypted string.
   */
  export function xorEncrypt(text: string, keyword: string): string;

  /**
   * Decrypts a Base64-encoded string using XOR cipher with the given keyword.
   * @param {string} encoded - The Base64-encoded string to decrypt.
   * @param {string} keyword - The keyword used for XOR decryption (must match the encryption keyword).
   * @returns {string} - The decrypted UTF-8 string.
   */
  export function xorDecrypt(encoded: string, keyword: string): string;

  /**
   * Delays execution for a specified duration in seconds and resolves to true when complete.
   * @param duration - The duration to wait in seconds.
   * @returns A promise that resolves to true after the specified duration.
   */
  export function sleep(duration: number): Promise<boolean>;

  /**
   * Downloads a file from the specified URL and saves it to the given file path.
   * @param {string} url - The URL of the file to download.
   * @param {string} filePath - The local file path where the downloaded file will be saved.
   * @returns {Promise<void>} - A promise that resolves when the download is complete.
   */
  export function downloadFile(url: string, filePath: string): Promise<void>;

  /**
   * Downloads a file from the specified URL and returns its content as a buffer.
   * @param {string} url - The URL of the file to download.
   * @returns {Promise<Buffer>} - A promise that resolves to the file's buffer.
   */
  export function downloadFileBuffer(url: string): Promise<Buffer>;

  /**
   * Writes a buffer to a file at the specified path using a stream.
   * @param {Buffer} buffer - The buffer to write to the file.
   * @param {string} filePath - The destination file path.
   * @returns {Promise<void>} - A promise that resolves when the file has been written.
   */
  export function bufferToFile(buffer: Buffer, filePath: string): Promise<void>;

  /**
   * Converts a buffer into a stream based on the environment.
   * @param buffer - The buffer to be converted into a stream.
   * @returns A stream that emits the buffer's content.
   */
  export function bufferToStream(buffer: Buffer | Uint8Array): Readable | ReadableStream;

  /**
   * Writes data from a stream to a file asynchronously.
   * @param stream - The stream source to write from.
   * @param filePath - The file path where the stream data will be written.
   * @returns Resolves on successful write completion, rejects on error.
   */
  export function streamToFile(stream: Readable | ReadableStream, filePath: string): Promise<void>;

  /**
   * Converts a file object to a Base64-encoded string asynchronously, optionally including the data URL prefix.
   * @param file - The file object to convert.
   * @param url - Whether to include the full data URL prefix in the result.
   * @returns A promise that resolves with the Base64-encoded string or the full data URL if specified.
   */
  export function fileToBase64(file: File, url?: boolean): Promise<string>;

  /**
   * Converts a Base64-encoded string to a binary format.
   * @param base64 - The Base64 string to convert.
   * @returns The binary representation of the Base64 string, either as Buffer or Uint8Array.
   */
  export function base64ToFile(base64: string): Buffer | Uint8Array | undefined;

  /**
   * Asynchronously writes data to a file only if the environment is not a browser.
   * @param filePath - Path where the data will be written.
   * @param data - Content to write to the file.
   * @param options - Write options, defaults to appending if the file exists.
   * @returns Resolves with true on successful write, false otherwise.
   */
  export function writeFile(
    filePath: string,
    data: any,
    options?: { flag?: string }
  ): Promise<boolean>;

  /**
   * Custom logging function that captures and formats log entries based on type.
   * @param log - The log content or Error object.
   * @param functionName - The name of the function being logged.
   * @param functionData - Additional data to log.
   * @param logFile - Whether to log to a file (default is true in non-browser environments).
   */
  export function logger(
    log: any | Error,
    functionName?: string,
    functionData?: any,
    logFile?: boolean
  ): void;

  /**
   * Attempts to retrieve a value from a cache or generates it using a callback if expired or not present.
   * @param cache - The cache storage object.
   * @param key - The cache key to look up or store the data under.
   * @param callback - Function to compute the value if necessary.
   * @param expiry - String indicating how long the cache value is considered fresh.
   * @returns The value from the cache or newly computed.
   */
  export function getCache<T>(
    cache: Map<string, { cacheValue: T; cacheDate: number }>,
    key: string,
    callback: () => Promise<T>,
    expiry?: string
  ): Promise<T | undefined>;

  /**
   * Checks if the cache contains a valid entry for a given key based on a specified expiry.
   * @param cache - The cache storage object.
   * @param key - The key to check in the cache.
   * @param expiry - The duration for which the cache entry is considered valid.
   * @returns True if a valid cache entry exists, false otherwise.
   */
  export function hasCache(
    cache: Map<string, { cacheValue: any; cacheDate: number }>,
    key: string,
    expiry?: string
  ): boolean;

  /**
   * Clears expired entries from the cache based on a specified expiry rule.
   * @param cache - The cache storage object to be cleaned.
   * @param expiry - The duration after which cache entries are considered expired.
   * @returns The updated cache object after removal of expired entries.
   */
  export function clearCache<T>(
    cache: Map<string, T>,
    expiry?: string
  ): Map<string, T>;

  /**
   * Determines if a cached date is still within its specified expiry period.
   * @param cacheDate - The timestamp of the cached entry to check.
   * @param expiry - The relative time string that specifies how long after the cacheDate the entry expires.
   * @returns True if the current date is before the expiry date, false otherwise.
   */
  export function checkCacheDate(cacheDate: number, expiry?: string): boolean;

  /**
   * Adjusts a given initial date by a specified amount of time defined in a string input.
   * @param input - Modification instruction, e.g., "+1 year", "-2 hours".
   * @param initialDate - The starting timestamp to modify.
   * @returns The modified date as a timestamp.
   */
  export function getModifiedDate(input: string, initialDate?: number | null): number;

  /**
   * Clears the current text selection in the browser window.
   */
  export function clearSelection(): boolean;

  /**
   * Creates a thumbnail from a given file, which can be a Buffer, a Base64 string, or a data URL.
   * @param file - The file or URL to be processed.
   * @param resize - The dimensions to resize the image to, or false to skip resizing.
   * @param quality - The quality of the output JPEG image.
   * @returns A promise that resolves with the thumbnail as a buffer.
   */
  export function getThumbnail(
    file: Buffer | string,
    resize: number | boolean,
    quality?: number
  ): Promise<Buffer | undefined>;

  /**
   * Generates a specific error message based on a given type and an optional insert parameter.
   * @param type - The error type identifier.
   * @param insert - Optional string to insert into the message for dynamic content.
   * @returns The generated error message.
   */
  export function getErrorMessage(type: string, insert?: string | null): string;

  /**
   * Executes a callback function and optionally repeats it after a set time interval.
   * @param callback - The function to execute and possibly repeat.
   * @param repeatTime - Time in seconds to wait before repeating the callback, or null to run only once.
   * @param attempt - The current retry attempt count.
   * @returns The result of the callback or false after exceeding retry limits.
   */
  export function run<T>(
    callback: () => Promise<T>,
    repeatTime?: number | null,
    attempt?: number
  ): Promise<T | boolean>;
}