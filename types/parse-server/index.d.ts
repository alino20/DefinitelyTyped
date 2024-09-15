// Import the type from the external package
import { FileSystemAdapter } from "@parse/fs-files-adapter";
import { RedisClientOptions, RedisClientType } from "@redis/client";
import { Express } from 'express';
import { Server } from 'http';

/** Adapters */

type Adapter<T> = string | T;
type ProtectedFields = any;
interface RequestKeywordDenylist {
  key: string,
  value: any,
}

/**
* @interface AnalyticsAdapter
*/
export interface AnalyticsAdapter {
  /**
  @param {any} parameters: the analytics request body, analytics info will be in the dimensions property
  @param {Request} req: the original http request
   */
  appOpened(parameters: any, req: Request): Promise<{}>;
  /**
  @param {String} eventName: the name of the custom eventName
  @param {any} parameters: the analytics request body, analytics info will be in the dimensions property
  @param {Request} req: the original http request
   */
  trackEvent(eventName: string, parameters: any, req: Request): Promise<{}>;
}


/*eslint no-unused-vars: "off"*/
/**
 * @interface
 */
export interface CacheAdapter {
  /**
   * Get a value in the cache
   * @param {String} key Cache key to get
   * @return {Promise} that will eventually resolve to the value in the cache.
   */
  get(key: string): Promise<string>;

  /**
   * Set a value in the cache
   * @param {String} key Cache key to set
   * @param {String} value Value to set the key
   * @param {String} ttl Optional TTL
   */
  put(key: string, value: string, ttl: string): void

  /**
   * Remove a value from the cache.
   * @param {String} key Cache key to remove
   */
  del(key: string): void

  /**
   * Empty a cache
   */
  clear(): void
}

type SchemaType = any;
type StorageClass = any;
type QueryType = any;
type mixed = unknown

export interface QueryOptions {
  skip?: number,
  limit?: number,
  acl?: string[],
  sort?: Record<string, number>,
  count?: boolean | number,
  keys?: string[],
  op?: string,
  distinct?: boolean,
  pipeline?: any,
  readPreference?: string,
  hint?: mixed,
  explain?: Boolean,
  caseInsensitive?: boolean,
  action?: string,
  addsField?: boolean,
  comment?: string,
}


export interface StorageAdapter {
  canSortOnJoinTables: boolean;
  schemaCacheTtl?: number;
  enableSchemaHooks: boolean;

  classExists(className: string): Promise<boolean>;
  setClassLevelPermissions(className: string, clps: any): Promise<void>;
  createClass(className: string, schema: SchemaType): Promise<void>;
  addFieldIfNotExists(className: string, fieldName: string, type: any): Promise<void>;
  updateFieldOptions(className: string, fieldName: string, type: any): Promise<void>;
  deleteClass(className: string): Promise<void>;
  deleteAllClasses(fast: boolean): Promise<void>;
  deleteFields(className: string, schema: SchemaType, fieldNames: string[]): Promise<void>;
  getAllClasses(): Promise<StorageClass[]>;
  getClass(className: string): Promise<StorageClass>;
  createObject(
    className: string,
    schema: SchemaType,
    object: any,
    transactionalSession?: any
  ): Promise<any>;
  deleteObjectsByQuery(
    className: string,
    schema: SchemaType,
    query: QueryType,
    transactionalSession?: any
  ): Promise<void>;
  updateObjectsByQuery(
    className: string,
    schema: SchemaType,
    query: QueryType,
    update: any,
    transactionalSession?: any
  ): Promise<any[]>;
  findOneAndUpdate(
    className: string,
    schema: SchemaType,
    query: QueryType,
    update: any,
    transactionalSession?: any
  ): Promise<any>;
  upsertOneObject(
    className: string,
    schema: SchemaType,
    query: QueryType,
    update: any,
    transactionalSession?: any
  ): Promise<any>;
  find(
    className: string,
    schema: SchemaType,
    query: QueryType,
    options: QueryOptions
  ): Promise<any[]>;
  ensureIndex(
    className: string,
    schema: SchemaType,
    fieldNames: string[],
    indexName?: string,
    caseSensitive?: boolean,
    options?: Object
  ): Promise<any>;
  ensureUniqueness(className: string, schema: SchemaType, fieldNames: string[]): Promise<void>;
  count(
    className: string,
    schema: SchemaType,
    query: QueryType,
    readPreference?: string,
    estimate?: boolean,
    hint?: mixed,
    comment?: string
  ): Promise<number>;
  distinct(
    className: string,
    schema: SchemaType,
    query: QueryType,
    fieldName: string
  ): Promise<any>;
  aggregate(
    className: string,
    schema: any,
    pipeline: any,
    readPreference?: string,
    hint?: mixed,
    explain?: boolean,
    comment?: string
  ): Promise<any>;
  performInitialization(options?: any): Promise<void>;
  watch(callback: () => void): void;

  // Indexing
  createIndexes(className: string, indexes: any, conn?: any): Promise<void>;
  getIndexes(className: string, connection?: any): Promise<void>;
  updateSchemaWithIndexes(): Promise<void>;
  setIndexesWithSchemaFormat(
    className: string,
    submittedIndexes: any,
    existingIndexes: any,
    fields: any,
    conn?: any
  ): Promise<void>;
  createTransactionalSession(): Promise<any>;
  commitTransactionalSession(transactionalSession: any): Promise<void>;
  abortTransactionalSession(transactionalSession: any): Promise<void>;
}

/**
 * @interface
 * Mail Adapter prototype
 * A MailAdapter should implement at least sendMail()
 */
export interface MailAdapter {
  /**
   * A method for sending mail
   * @param options would have the parameters
   * - to: the recipient
   * - text: the raw text of the message
   * - subject: the subject of the email
   */
  sendMail: {(options: {
    to: string,
    text: string,
    subject: string
  }): Promise<void>}
  // Marked as optional in source code
  // sendVerificationEmail?: {(options: { link:string, appName:string, user:any }):Promise<void>}
  // sendPasswordResetEmail?: {(options: { link:string, appName:string, user:any }):Promise<void>}


}

type Config = Record<string, any>

/**
 * @interface
 */
export interface FilesAdapter {
  /** Responsible for storing the file in order to be retrieved later by its filename
   *
   * @param {string} filename - the filename to save
   * @param {any} data - the buffer of data from the file
   * @param {string} contentType - the supposed contentType
   * @param {object} options - (Optional) options to be passed to file adapter (S3 File Adapter Only)
   * - tags: object containing key value pairs that will be stored with file
   * - metadata: object containing key value pairs that will be sotred with file (https://docs.aws.amazon.com/AmazonS3/latest/user-guide/add-object-metadata.html)
   * @return {Promise} a promise that should fail if the storage didn't succeed
   */
  createFile(filename: string, data: any, contentType: string, options: Object): Promise<void>

  /** Responsible for deleting the specified file
   *
   * @param {string} filename - the filename to delete
   *
   * @return {Promise} a promise that should fail if the deletion didn't succeed
   */
  deleteFile(filename: string): Promise<void>

  /** Responsible for retrieving the data of the specified file
   *
   * @param {string} filename - the name of file to retrieve
   *
   * @return {Promise} a promise that should pass with the file data or fail on error
   */
  getFileData(filename: string): Promise<any>

  /** Returns an absolute URL where the file can be accessed
   *
   * @param {Config} config - server configuration
   * @param {string} filename
   *
   * @return {string | Promise<string>} Absolute URL
   */
  getFileLocation(config: Config, filename: string): string | Promise<string>
}

/**
* @interface
* Logger Adapter
* Allows you to change the logger mechanism
* Default is WinstonLoggerAdapter.js
*/
export interface LoggerAdapter {
  log(level: string, message: string): void
}

declare class PubSubAdapter {
  /**
 * @returns {PubSubAdapter.Publisher}
 */
  static createPublisher(): Publisher
  /**
   * @returns {PubSubAdapter.Subscriber}
   */
  static createSubscriber(): Subscriber;
}

/**
* @interface Publisher
*/
export interface Publisher {
  /**
   * @param {String} channel the channel in which to publish
   * @param {String} message the message to publish
   */
  publish(channel: string, message: string): void;
}

/**
 * @interface Subscriber
 * @memberof PubSubAdapter
 */
export interface Subscriber {
  /**
   * called when a new subscription the channel is required
   * @param {String} channel the channel to subscribe
   */
  subscribe(channel: string): void;

  /**
   * called when the subscription from the channel should be stopped
   * @param {String} channel
   */
  unsubscribe(channel: string): void;
}

declare class WSSAdapter {
  constructor(options: Object);
  start(options: Object): void;
  close(): void;
}

/** Options */

export interface SchemaOptions {
  afterMigration?: Function  //  Execute a callback after running schema migrations.
  beforeMigration?: Function // Execute a callback before running schema migrations.
  definitions?: any // Rest representation on Parse.Schema https://docs.parseplatform.org/rest/guide/#adding-a-schema
  deleteExtraFields?: boolean // Is true if Parse Server should delete any fields not defined in a schema definition. This should only be used during development.
  lockSchemas?: Boolean // Is true if Parse Server will reject any attempts to modify the schema while the server is running.
  recreateModifiedFields?: Boolean // Is true if Parse Server should recreate any fields that are different between the current database schema and theschema definition. This should only be used during development.
  strict?: Boolean // Is true if Parse Server should exit if schema update fail.
}

type Union = string | Function

export interface ParseServerOptions {
  accountLockout?: AccountLockoutOptions //  The account lockout policy for failed login attempts.
  allowClientClassCreation?: Boolean //  Enable (or disable) client class creation, defaults to false
  allowCustomObjectId?: Boolean //  Enable (or disable) custom objectId
  allowExpiredAuthDataToken?: Boolean //  Allow a user to log in even if the 3rd party authentication token that was used to sign in to their account has expired. If this is set to `false`, then the token will be validated every time the user signs in to their account. This refers to the token that is stored in the `_User.authData` field. Defaults to `false`.
  allowHeaders?: String[] //  Add headers to Access-Control-Allow-Headers
  allowOrigin?: String | String[] //  Sets origins for Access-Control-Allow-Origin. This can be a string for a single origin or an array of strings for multiple origins.
  analyticsAdapter?: Adapter<AnalyticsAdapter> //  Adapter module for the analytics
  appId?: String //  Your Parse Application ID
  appName?: String //  Sets the app name
  auth?: Object //  Configuration for your authentication providers, as stringified JSON. See http://docs.parseplatform.org/parse-server/guide/#oauth-and-3rd-party-authentication
  cacheAdapter?: Adapter<CacheAdapter> //  Adapter module for the cache
  cacheMaxSize?: Number //  Sets the maximum size for the in memory cache, defaults to 10000
  cacheTTL?: Number //  Sets the TTL for the in memory cache (in ms), defaults to 5000 (5 seconds)
  clientKey?: String //  Key for iOS, MacOS, tvOS clients
  cloud: String //  Full path to your cloud code main.js
  cluster?: Number | Boolean //  Run with cluster, optionally set the number of processes default to os.cpus().length
  collectionPrefix?: String //  A collection prefix for the classes
  convertEmailToLowercase?: Boolean //  Optional. If set to `true`, the `email` property of a user is automatically converted to lowercase before being stored in the database. Consequently, queries must match the case as stored in the database, which would be lowercase in this scenario. If `false`, the `email` property is stored as set, without any case modifications. Default is `false`.
  convertUsernameToLowercase?: Boolean //  Optional. If set to `true`, the `username` property of a user is automatically converted to lowercase before being stored in the database. Consequently, queries must match the case as stored in the database, which would be lowercase in this scenario. If `false`, the `username` property is stored as set, without any case modifications. Default is `false`.
  customPages?: CustomPagesOptions //  custom pages for password validation and reset
  databaseAdapter?: Adapter<StorageAdapter> //  Adapter module for the database; any options that are not explicitly described here are passed directly to the database client.
  databaseOptions?: DatabaseOptions //  Options to pass to the database client
  databaseURI?: String //  The full URI to your database. Supported databases are mongodb or postgres.
  defaultLimit?: Number //  Default value for limit option on queries, defaults to `100`.
  directAccess?: Boolean //  Set to `true` if Parse requests within the same Node.js environment as Parse Server should be routed to Parse Server directly instead of via the HTTP interface. Default is `false`.<br><br>If set to `false` then Parse requests within the same Node.js environment as Parse Server are executed as HTTP requests sent to Parse Server via the `serverURL`. For example, a `Parse.Query` in Cloud Code is calling Parse Server via a HTTP request. The server is essentially making a HTTP request to itself, unnecessarily using network resources such as network ports.<br><br>⚠️ In environments where multiple Parse Server instances run behind a load balancer and Parse requests within the current Node.js environment should be routed via the load balancer and distributed as HTTP requests among all instances via the `serverURL`, this should be set to `false`.
  dotNetKey?: String //  Key for Unity and .Net SDK
  emailAdapter?: Adapter<MailAdapter> | Object //  Adapter module for email sending
  emailVerifyTokenReuseIfValid?: Boolean //  Set to `true` if a email verification token should be reused in case another token is requested but there is a token that is still valid, i.e. has not expired. This avoids the often observed issue that a user requests multiple emails and does not know which link contains a valid token because each newly generated token would invalidate the previous token.<br><br>Default is `false`.<br>Requires option `verifyUserEmails: true`.
  emailVerifyTokenValidityDuration?: Number //  Set the validity duration of the email verification token in seconds after which the token expires. The token is used in the link that is set in the email. After the token expires, the link becomes invalid and a new link has to be sent. If the option is not set or set to `undefined`, then the token never expires.<br><br>For example, to expire the token after 2 hours, set a value of 7200 seconds (= 60 seconds  br><br>Default is `undefined`.<br>Requires option `verifyUserEmails: true`.
  enableAnonymousUsers?: Boolean //  Enable (or disable) anonymous users, defaults to true
  enableCollationCaseComparison?: Boolean //  Optional. If set to `true`, the collation rule of case comparison for queries and indexes is enabled. Enable this option to run Parse Server with MongoDB Atlas Serverless or AWS Amazon DocumentDB. If `false`, the collation rule of case comparison is disabled. Default is `false`.
  enableExpressErrorHandler?: Boolean //  Enables the default express error handler for all errors
  encodeParseObjectInCloudFunction?: Boolean //  If set to `true`, a `Parse.Object` that is in the payload when calling a Cloud Function will be converted to an instance of `Parse.Object`. If `false`, the object will not be converted and instead be a plain JavaScript object, which contains the raw data of a `Parse.Object` but is not an actual instance of `Parse.Object`. Default is `false`. <br><br>ℹ️ The expected behavior would be that the object is converted to an instance of `Parse.Object`, so you would normally set this option to `true`. The default is `false` because this is a temporary option that has been introduced to avoid a breaking change when fixing a bug where JavaScript objects are not converted to actual instances of `Parse.Object`.
  encryptionKey?: String //  Key for encrypting your files
  enforcePrivateUsers?: Boolean //  Set to true if new users should be created without public read and write access.
  expireInactiveSessions?: Boolean //  Sets whether we should expire the inactive sessions, defaults to true. If false, all new sessions are created with no expiration date.
  extendSessionOnUse?: Boolean //  Whether Parse Server should automatically extend a valid session by the sessionLength. In order to reduce the number of session updates in the database, a session will only be extended when a request is received after at least half of the current session's lifetime has passed.
  fileKey?: String //  Key for your files
  filesAdapter?: Adapter<FilesAdapter> //  Adapter module for the files sub-system
  fileUpload?: FileUploadOptions //  Options for file uploads
  graphQLPath?: String //  Mount path for the GraphQL endpoint, defaults to /graphql
  graphQLSchema?: String //  Full path to your GraphQL custom schema.graphql file
  host?: String //  The host to serve ParseServer on, defaults to 0.0.0.0
  idempotencyOptions?: IdempotencyOptions //  Options for request idempotency to deduplicate identical requests that may be caused by network issues. Caution, this is an experimental feature that may not be appropriate for production.
  javascriptKey?: String //  Key for the Javascript SDK
  jsonLogs?: Boolean //  Log as structured JSON objects
  liveQuery?: LiveQueryOptions //  parse-server's LiveQuery configuration object
  liveQueryServerOptions?: LiveQueryServerOptions //  Live query server configuration options (will start the liveQuery server)
  loggerAdapter?: Adapter<LoggerAdapter> //  Adapter module for the logging sub-system
  logLevel?: String //  Sets the level for logs
  logLevels?: LogLevels //  (Optional) Overrides the log levels used internally by Parse Server to log events.
  logsFolder?: String //  Folder for the logs (defaults to './logs'); set to null to disable file based logging
  maintenanceKey?: String //  (Optional) The maintenance key is used for modifying internal and read-only fields of Parse Server.<br><br>⚠️ This key is not intended to be used as part of a regular operation of Parse Server. This key is intended to conduct out-of-band changes such as one-time migrations or data correction tasks. Internal fields are not officially documented and may change at any time without publication in release changelogs. We strongly advice not to rely on internal fields as part of your regular operation and to investigate the implications of any planned changes  the source coderrent version of Parse Server.
  maintenanceKeyIps?: String[] //  (Optional) Restricts the use of maintenance key permissions to a list of IP addresses or ranges.<br><br>This option accepts a list of single IP addresses, for example `['10.0.0.1', '10.0.0.2']`. You can also use CIDR notation to specify an IP address range, for example `['10.0.1.0/24']`.<br><br><b>Special scenarios:</b><br>- Setting an empty array `[]` means that the maintenance key cannot be used even in Parse Server Cloud Code. This value cannot be set via an environment variable as there is no way to pass an empty array to Parse Server via an environment variable.<br>- Setting `['0.0.0.0/0', '::0']` means to allow any IPv4 and IPv6 address to use the maintenance key and effectively disables the IP filter.<br><br><b>Considerations:</b><br>- IPv4 and IPv6 addresses are not compared against each other. Each IP version (IPv4 and IPv6) needs to be considered separately. For example, `['0.0.0.0/0']` allows any IPv4 address and blocks every IPv6 address. Conversely, `['::0']` allows any IPv6 address and blocks every IPv4 address.<br>- Keep in mind that the IP version in use depends on the network stack of the environment in which Parse Server runs. A local environment may use a different IP version than a remote environment. For example, it's possible that locally the value `['0.0.0.0/0']` allows the request IP because the environment is using IPv4, but when Parse Server is deployed remotely the request IP is blocked because the remote environment is using IPv6.<br>- When setting the option via an environment variable the notation is a comma-separated string, for example `"0.0.0.0/0,::0"`.<br>- IPv6 zone indices (`%` suffix) are not supported, for example `fe80::1%eth0`, `fe80::1%1` or `::1%lo`.<br><br>Defaults to `['127.0.0.1', '::1']` which means that only `localhost`, the server instance on which Parse Server runs, is allowed to use the maintenance key.
  masterKey?: String //  Your Parse Master Key
  masterKeyIps?: String[] //  (Optional) Restricts the use of master key permissions to a list of IP addresses or ranges.<br><br>This option accepts a list of single IP addresses, for example `['10.0.0.1', '10.0.0.2']`. You can also use CIDR notation to specify an IP address range, for example `['10.0.1.0/24']`.<br><br><b>Special scenarios:</b><br>- Setting an empty array `[]` means that the master key cannot be used even in Parse Server Cloud Code. This value cannot be set via an environment variable as there is no way to pass an empty array to Parse Server via an environment variable.<br>- Setting `['0.0.0.0/0', '::0']` means to allow any IPv4 and IPv6 address to use the master key and effectively disables the IP filter.<br><br><b>Considerations:</b><br>- IPv4 and IPv6 addresses are not compared against each other. Each IP version (IPv4 and IPv6) needs to be considered separately. For example, `['0.0.0.0/0']` allows any IPv4 address and blocks every IPv6 address. Conversely, `['::0']` allows any IPv6 address and blocks every IPv4 address.<br>- Keep in mind that the IP version in use depends on the network stack of the environment in which Parse Server runs. A local environment may use a different IP version than a remote environment. For example, it's possible that locally the value `['0.0.0.0/0']` allows the request IP because the environment is using IPv4, but when Parse Server is deployed remotely the request IP is blocked because the remote environment is using IPv6.<br>- When setting the option via an environment variable the notation is a comma-separated string, for example `"0.0.0.0/0,::0"`.<br>- IPv6 zone indices (`%` suffix) are not supported, for example `fe80::1%eth0`, `fe80::1%1` or `::1%lo`.<br><br>Defaults to `['127.0.0.1', '::1']` which means that only `localhost`, the server instance on which Parse Server runs, is allowed to use the master key.
  maxLimit?: Number //  Max value for limit option on queries, defaults to unlimited
  maxLogFiles?: Number | String //  Maximum number of logs to keep. If not set, no logs will be removed. This can be a number of files or number of days. If using days, add 'd' as the suffix. (default: null)
  maxUploadSize?: String //  Max file size for uploads, defaults to 20mb
  middleware?: Union //  middleware for express server, can be string or function
  mountGraphQL?: Boolean //  Mounts the GraphQL endpoint
  mountPath?: String //  Mount path for the server, defaults to /parse
  mountPlayground?: Boolean //  Mounts the GraphQL Playground - never use this option in production
  objectIdSize?: Number //  Sets the number of characters in generated object id's, default 10
  pages?: PagesOptions //  The options for pages such as password reset and email verification. Caution, this is an experimental feature that may not be appropriate for production.
  passwordPolicy?: PasswordPolicyOptions //  The password policy for enforcing password related rules.
  playgroundPath?: String //  Mount path for the GraphQL Playground, defaults to /playground
  port?: Number //  The port to run the ParseServer, defaults to 1337.
  preserveFileName?: Boolean //  Enable (or disable) the addition of a unique hash to the file names
  preventLoginWithUnverifiedEmail?: Boolean //  Set to `true` to prevent a user from logging in if the email has not yet been verified and email verification is required.<br><br>Default is `false`.<br>Requires option `verifyUserEmails: true`.
  preventSignupWithUnverifiedEmail?: Boolean //  If set to `true` it prevents a user from signing up if the email has not yet been verified and email verification is required. In that case the server responds to the sign-up with HTTP status 400 and a Parse Error 205 `EMAIL_NOT_FOUND`. If set to `false` the server responds with HTTP status 200, and client SDKs return an unauthenticated Parse User without session token. In that case subsequent requests fail until the user's email address is verified.<br><br>Default is `false`.<br>Requires option `verifyUserEmails: true`.
  protectedFields?: ProtectedFields //  Protected fields that should be treated with extra security when fetching details.
  publicServerURL?: String //  Public URL to your parse server with http:// or https://.
  push?: any //  Configuration for push, as stringified JSON. See http://docs.parseplatform.org/parse-server/guide/#push-notifications
  rateLimit?: RateLimitOptions[] //  Options to limit repeated requests to Parse Server APIs. This can be used to protect sensitive endpoints such as `/requestPasswordReset` from brute-force attacks or Parse Server as a whole from denial-of-service (DoS) attacks.<br><br>ℹ️ Mind the following limitations:<br>- rate limits applied per IP address; this limits protection against distributed denial-of-service (DDoS) attacks where many requests are coming from various IP addresses<br>- if multiple Parse Server instances are behind a load balancer or ran in a cluster, each instance will calculate it's own request rates, independent from other instances; this limits the applicability of this feature when using a load balancer and another rate limiting solution that takes requests across all instances into account may be more suitable<br>- this feature provides basic protection against denial-of-service attacks, but a more sophisticated solution works earlier in the request flow and prevents a malicious requests to even reach a server instance; it's therefore recommended to implement a solution according to architecture and user case.
  readOnlyMasterKey?: String //  Read-only key, which has the same capabilities as MasterKey without writes
  requestKeywordDenylist?: RequestKeywordDenylist[] //  An array of keys and values that are prohibited in database read and write requests to prevent potential security vulnerabilities. It is possible to specify only a key (`":"..."`),: "key // only a value (`":"..."`): "value // or a key-value pair (`":"..."`).: "key //":"...","value The specification can use the following types: `boolean`, `numeric` or `string`, where `string` will be interpreted as a regex notation. Request data is deep-scanned for matching definitions to detect also any nested occurrences. Defaults are patterns that are likely to be used in malicious requests. Setting this option will override the default patterns.
  restAPIKey?: String //  Key for REST calls
  revokeSessionOnPasswordReset?: Boolean //  When a user changes their password, either through the reset password email or while logged in, all sessions are revoked if this is true. Set to false if you don't want to revoke sessions.
  scheduledPush?: Boolean /** Configuration for push scheduling, defaults to false. */
  schema?: SchemaOptions //  Defined schema
  security?: SecurityOptions //  The security options to identify and report weak security settings.
  sendUserEmailVerification?: Boolean //  Set to `false` to prevent sending of verification email. Supports a function with a return value of `true` or `false` for conditional email sending.<br><br>Default is `true`.<br>
  serverCloseComplete?: Function //  Callback when server has closed
  serverURL?: String //  URL to your parse server with http:// or https://.
  sessionLength?: Number //  Session duration, in seconds, defaults to 1 year
  silent?: Boolean //  Disables console output
  startLiveQueryServer?: Boolean //  Starts the liveQuery server
  trustProxy?: any //  The trust proxy settings. It is important to understand the exact setup of the reverse proxy, since this setting will trust values provided in the Parse Server API request. See the <a href="https://expressjs.com/en/guide/behind-proxies.html">express trust proxy settings</a> documentation. Defaults to `false`.
  userSensitiveFields?: String[] //  Personally identifiable information fields in the user table the should be removed for non-authorized users. Deprecated @see protectedFields
  verbose?: Boolean //  Set the logging to verbose
  verifyUserEmails?: Boolean //  Set to `true` to require users to verify their email address to complete the sign-up process. Supports a function with a return value of `true` or `false` for conditional verification.<br><br>Default is `false`.
  webhookKey?: String //  Key sent with outgoing webhook calls
}


export interface RateLimitOptions {

  errorResponseMessage?: String //  The error message that should be returned in the body of the HTTP 429 response when the rate limit is hit. Default is `Too many requests.`.
  includeInternalRequests?: Boolean //  Optional, if `true` the rate limit will also apply to requests that are made in by Cloud Code, default is `false`. Note that a public Cloud Code function that triggers internal requests may circumvent rate limiting and be vulnerable to attacks.
  includeMasterKey?: Boolean //  Optional, if `true` the rate limit will also apply to requests using the `masterKey`, default is `false`. Note that a public Cloud Code function that triggers internal requests using the `masterKey` may circumvent rate limiting and be vulnerable to attacks.
  redisUrl?: String //  Optional, the URL of the Redis server to store rate limit data. This allows to rate limit requests for multiple servers by calculating the sum of all requests across all servers. This is useful if multiple servers are processing requests behind a load balancer. For example, the limit of 10 requests is reached if each of 2 servers processed 5 requests.
  requestCount?: Number //  The number of requests that can be made per IP address within the time window set in `requestTimeWindow` before the rate limit is applied.
  requestMethods?: String[] //  Optional, the HTTP request methods to which the rate limit should be applied, default is all methods.
  requestPath?: String //  The path of the API route to be rate limited. Route paths, in combination with a request method, define the endpoints at which requests can be made. Route paths can be strings, string patterns, or regular expression. See: https://expressjs.com/en/guide/routing.html
  requestTimeWindow?: Number //  The window of time in milliseconds within which the number of requests set in `requestCount` can be made before the rate limit is applied.
  zone?: String //  The type of rate limit to apply. The following types are supported:<br><br>- `global`: rate limit based on the number of requests made by all users <br>- `ip`: rate limit based on the IP address of the request <br>- `user`: rate limit based on the user ID of the request <br>- `session`: rate limit based on the session token of the request <br><br><br>:default: 'ip'

}

/**
* The check state.
*/
export interface CheckState { none: 'none', fail: 'fail', success: 'success' }

declare class Check {
  /**
   * Constructs a new security check.
   * @param {Object} params The parameters.
   * @param {String} params.title The title.
   * @param {String} params.warning The warning message if the check fails.
   * @param {String} params.solution The solution to fix the check.
   * @param {Promise} params.check The check as synchronous or asynchronous function.
   */
  constructor({ }: { title: string; warning: string; solution: string; check: Promise<any>; });

  /**
   * Returns the current check state.
   * @return {CheckState} The check state.
   */
  checkState(): CheckState;

  run(): Promise<void>;

  /**
   * Validates the constructor parameters.
   * @param {Object} params The parameters to validate.
   */
  _validateParams(params: object): void;
}

export interface CheckGroup {
  setName(): void
  name(): string
  setChecks(): void
  checks(): Check[]
  run(): Promise<void>
}


export interface SecurityOptions {
  checkGroups?: CheckGroup[]  // The security check groups to run. This allows to add custom security checks or override existing ones. Default are the groups defined in `CheckGroups.js`.
  enableCheck?: Boolean  // Is true if Parse Server should check for weak security settings.
  enableCheckLog?: Boolean  // Is true if the security check report should be written to logs. This should only be enabled temporarily to not expose weak security settings in logs. 
}

export interface PagesOptions {

  customRoutes?: PagesRoute[] // The custom routes.
  customUrls?: PagesCustomUrlsOptions // The URLs to the custom pages.
  enableLocalization?: Boolean // Is true if pages should be localized; this has no effect on custom page redirects.
  enableRouter?: Boolean // Is true if the pages router should be enabled; this is required for any of the pages options to take effect. Caution, this is an experimental feature that may not be appropriate for production.
  forceRedirect?: Boolean // Is true if responses should always be redirects and never content, false if the response type should depend on the request type (GET request -> content response; POST request -> redirect response).
  localizationFallbackLocale?: String // The fallback locale for localization if no matching translation is provided for the given locale. This is only relevant when providing translation resources via JSON file.
  localizationJsonPath?: String // The path to the JSON file for localization; the translations will be used to fill template placeholders according to the locale.
  pagesEndpoint?: String // The API endpoint for the pages. Default is 'apps'.
  pagesPath?: String // The path to the pages directory; this also defines where the static endpoint '/apps' points to. Default is the './public/' directory.
  placeholders?: Object // The placeholder keys and values which will be filled in pages; this can be a simple object or a callback function.
}

export interface PagesRoute {
  handler: Function // The route handler that is an async function.
  method: String // The route method, e.g. 'GET' or 'POST'.
  path: String // The route path.
}

export interface PagesCustomUrlsOptions {
  emailVerificationLinkExpired?: String // The URL to the custom page for email verification -> link expired.
  emailVerificationLinkInvalid?: String // The URL to the custom page for email verification -> link invalid.
  emailVerificationSendFail?: String // The URL to the custom page for email verification -> link send fail.
  emailVerificationSendSuccess?: String // The URL to the custom page for email verification -> resend link -> success.
  emailVerificationSuccess?: String // The URL to the custom page for email verification -> success.
  passwordReset?: String // The URL to the custom page for password reset.
  passwordResetLinkInvalid?: String // The URL to the custom page for password reset -> link invalid.
  passwordResetSuccess?: String // The URL to the custom page for password reset -> success.
}

export interface CustomPagesOptions {
  choosePassword?: String // The URL to the custom page for choosing a password.
  expiredVerificationLink?: String // The URL to the custom page for expired verification link.
  invalidLink?: String // The URL to the custom page for invalid link.
  invalidPasswordResetLink?: String // The URL to the custom page for invalid password reset link.
  invalidVerificationLink?: String // The URL to the custom page for invalid verification link.
  linkSendFail?: String // The URL to the custom page for link send fail.
  linkSendSuccess?: String // The URL to the custom page for link send success.
  parseFrameURL?: String // The URL to the custom page for masking user-facing pages.
  passwordResetSuccess?: String // The URL to the custom page for password reset success.
  verifyEmailSuccess?: String // The URL to the custom page for verify email success.
}

export interface LiveQueryOptions {
  classNames?: String[] // The parse-server's LiveQuery classNames
  pubSubAdapter?: Adapter<PubSubAdapter> // LiveQuery pubsub adapter
  redisOptions?: any // parse-server's LiveQuery redisOptions
  redisURL?: String // parse-server's LiveQuery redisURL
  wssAdapter?: Adapter<WSSAdapter> // Adapter module for the WebSocketServer
}

export interface LiveQueryServerOptions {
  appId?: String // This string should match the appId in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same appId.
  cacheTimeout?: Number // Number in milliseconds. When clients provide the sessionToken to the LiveQuery server, the LiveQuery server will try to fetch its ParseUser's objectId from parse server and store it in the cache. The value defines the duration of the cache. Check the following Security section and our protocol specification for details, defaults to 5 * 1000 ms (5 seconds).
  keyPairs?: any // A JSON object that serves as a whitelist of keys. It is used for validating clients when they try to connect to the LiveQuery server. Check the following Security section and our protocol specification for details.
  logLevel?: String // This string defines the log level of the LiveQuery server. We support VERBOSE, INFO, ERROR, NONE, defaults to INFO.
  masterKey?: String // This string should match the masterKey in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same masterKey.
  port?: Number // The port to run the LiveQuery server, defaults to 1337.
  pubSubAdapter?: Adapter<PubSubAdapter> // LiveQuery pubsub adapter
  redisOptions?: any // parse-server's LiveQuery redisOptions
  redisURL?: String // parse-server's LiveQuery redisURL
  serverURL?: String // This string should match the serverURL in use by your Parse Server. If you deploy the LiveQuery server alongside Parse Server, the LiveQuery server will try to use the same serverURL.
  websocketTimeout?: Number // Number of milliseconds between ping/pong frames. The WebSocket server sends ping/pong frames to the clients to keep the WebSocket alive. This value defines the interval of the ping/pong frame from the server to clients, defaults to 10 * 1000 ms (10 s).
  wssAdapter?: Adapter<WSSAdapter> // Adapter module for the WebSocketServer
}

export interface IdempotencyOptions {
  paths?: String[] // An array of paths for which the feature should be enabled. The mount path must not be included, for example instead of `/parse/functions/myFunction` specifiy `functions/myFunction`. The entries are interpreted as regular expression, for example `functions/.*` matches all functions, `jobs/.*` matches all jobs, `classes/.*` matches all classes, `.*` matches all paths.
  ttl?: Number // The duration in seconds after which a request record is discarded from the database, defaults to 300s.
}

export interface AccountLockoutOptions {
  duration?: Number // Set the duration in minutes that a locked-out account remains locked out before automatically becoming unlocked.<br><br>Valid values are greater than `0` and less than `100000`.
  threshold?: Number // Set the number of failed sign-in attempts that will cause a user account to be locked. If the account is locked. The account will unlock after the duration set in the `duration` option has passed and no further login attempts have been made.<br><br>Valid values are greater than `0` and less than `1000`.
  unlockOnPasswordReset?: Boolean // Set to `true`  if the account should be unlocked after a successful password reset.<br><br>Default is `false`.<br>Requires options `duration` and `threshold` to be set.
}

export interface PasswordPolicyOptions {
  doNotAllowUsername?: Boolean // Set to `true` to disallow the username as part of the password.<br><br>Default is `false`.
  maxPasswordAge?: Number // Set the number of days after which a password expires. Login attempts fail if the user does not reset the password before expiration.
  maxPasswordHistory?: Number // Set the number of previous password that will not be allowed to be set as new password. If the option is not set or set to `0`, no previous passwords will be considered.<br><br>Valid values are >= `0` and <= `20`.<br>Default is `0`.
  resetPasswordSuccessOnInvalidEmail?: Boolean // Set to `true` if a request to reset the password should return a success response even if the provided email address is invalid, or `false` if the request should return an error response if the email address is invalid.<br><br>Default is `true`.
  resetTokenReuseIfValid?: Boolean // Set to `true` if a password reset token should be reused in case another token is requested but there is a token that is still valid, i.e. has not expired. This avoids the often observed issue that a user requests multiple emails and does not know which link contains a valid token because each newly generated token would invalidate the previous token.<br><br>Default is `false`.
  resetTokenValidityDuration?: Number // Set the validity duration of the password reset token in seconds after which the token expires. The token is used in the link that is set in the email. After the token expires, the link becomes invalid and a new link has to be sent. If the option is not set or set to `undefined`, then the token never expires.<br><br>For example, to expire the token after 2 hours, set a value of 7200 seconds (= 60 seconds * 60 minutes * 2 hours).<br><br>Default is `undefined`.
  validationError?: String // Set the error message to be sent.<br><br>Default is `Password does not meet the Password Policy requirements.`
  validatorCallback?: Function // Set a callback function to validate a password to be accepted.<br><br>If used in combination with `validatorPattern`, the password must pass both to be accepted.
  validatorPattern?: RegExp // Set a regular expression to validate a password to be accepted.<br><br>If used in combination with `validatorCallback`, the password must pass both to be
}

export interface FileUploadOptions {
  enableForAnonymousUser?: Boolean // Is true if file upload should be allowed for anonymous users.
  enableForAuthenticatedUser?: Boolean // Is true if file upload should be allowed for authenticated users.
  enableForPublic?: Boolean // Is true if file upload should be allowed for anyone, regardless of user authentication.
  fileExtensions?: String[] // Sets the allowed file extensions for uploading files. The extension is defined as an array of file extensions, or a regex pattern.<br><br>It is recommended to restrict the file upload extensions as much as possible. HTML files are especially problematic as they may be used by an attacker who uploads a HTML form to look legitimate under your app's domain name, or to compromise the session token of another user via accessing the browser's local storage.<br><br>Defaults to `^(?!(h|H)(t|T)(m|M)(l|L)?$)` which allows any file extension except HTML files.
}

export interface DatabaseOptions {
  enableSchemaHooks?: boolean // Enables database real-time hooks to update single schema cache. Set to `true` if using multiple Parse Servers instances connected to the same database. Failing to do so will cause a schema change to not propagate to all instances and re-syncing will only happen when the instances restart. To use this feature with MongoDB, a replica set cluster with [change stream](https://docs.mongodb.com/manual/changeStreams/#availability) support is required.
  maxPoolSize?: Number // The MongoDB driver option to set the maximum number of opened, cached, ready-to-use database connections maintained by the driver.
  maxStalenessSeconds?: number // The MongoDB driver option to set the maximum replication lag for reads from secondary nodes.
  maxTimeMS?: Number //  The MongoDB driver option to set a cumulative time limit in milliseconds for processing operations on a cursor.
  retryWrites?: Boolean //  The MongoDB driver option to set whether to retry failed writes.
  schemaCacheTtl?: Number //  The duration in seconds after which the schema cache expires and will be refetched from the database. Use this option if using multiple Parse Servers instances connected to the same database. A low duration will cause the schema cache to be updated too often, causing unnecessary database reads. A high duration will cause the schema to be updated too rarely, increasing the time required until schema changes propagate to all server instances. This feature can be used as an alternative or in conjunction with the option `enableSchemaHooks`. Default is infinite which means the schema cache never expires.
}

declare class AuthAdapter {
  enabled?: boolean // Is `true` if the auth adapter is enabled, `false` otherwise.
}

export interface LogLevels {
  cloudFunctionError?: string; // Log level used by the Cloud Code Functions on error. Default is `error`.
  cloudFunctionSuccess?: string; // Log level used by the Cloud Code Functions on success. Default is `info`.
  triggerAfter?: string; // Log level used by the Cloud Code Triggers `afterSave`, `afterDelete`, `afterFind`, `afterLogout`. Default is `info`.
  triggerBeforeError?: string; // Log level used by the Cloud Code Triggers `beforeSave`, `beforeDelete`, `beforeFind`, `beforeLogin` on error. Default is `error`.
  triggerBeforeSuccess?: string; // Log level used by the Cloud Code Triggers `beforeSave`, `beforeDelete`, `beforeFind`, `beforeLogin` on success. Default is `info`.
}

type METHOD = "POST" | "GET" | "PUT" | "DELETE"
type RequestHandler = (req: Request) => Promise<{
  status?: number;
  response: Object,
  location?: string
}>

interface Route {
  path: string;
  method: METHOD,
  handler: RequestHandler;
}



declare class PromiseRouter {
  constructor(routes: Route[], appId: string);

  kir: Express.Response

  mountRoutes(): void
  merge(router: Route): void
  route(method: METHOD, path: string, ...handlers: Function[]): void;
  match(method: METHOD, path: string): {
    handler: RequestHandler,
    params: any
  }
  mountOnto(expressApp: Express.Application): Express.Application
  expressRouter(): Express.Application
  tryRouteRequest(method: METHOD, path: string, request: Request): Promise<{
    status?: number;
    response: Object,
    location?: string
  }>
}

declare class ParseLiveQueryServer {
  clients: Map<string, Object>;
  subscriptions: Object;
  parseWebSocketServer: Object;
  keyPairs: any;
  // The subscriber we use to get object update from publisher
  subscriber: Object;

  constructor(server: any, config: any, parseServerConfig: any)

  connect(): Promise<void>;

  // _createSubscribers is not included since it's private
}

declare class ParseServer {
  constructor(options: ParseServerOptions);

  start(): Promise<this>;

  get app(): Express

  handleShutdown(): Promise<void>

  static app(options: {
    maxUploadSize: string
    appId: string
    directAccess: boolean
    pages: any
    rateLimit: any[]
    state: string
  }): Express;

  static promiseRouter(params: { appId: string }): PromiseRouter;

  startApp(options: ParseServerOptions): Promise<this>

  static startApp(options: ParseServerOptions): Promise<ParseServer>

  static createLiveQueryServer(
    httpServer: Server | undefined,
    config: LiveQueryServerOptions,
    options: ParseServerOptions
  ): Promise<ParseLiveQueryServer>

  static verifyServerUrl(): Promise<boolean | undefined>
}

/**
 * @deprecated S3Adapter is no longer provided by parse-server.
 * Please install @parse/s3-files-adapter.
 */
declare function S3Adapter(): never;

/**
 * @deprecated S3Adapter is no longer provided by parse-server.
 * Please install @parse/gcs-files-adapter.
 */
declare function GCSAdapter(): never;

declare class InMemoryCacheAdapter {
  constructor(options?: { ttl?: number, maxSize?: number })

  get(key: string): Promise<any>

  set(key: string, value: any): Promise<void>

  del(key: string): Promise<void>

  clear(): Promise<void>
}

declare class NullCacheAdapter {
  constructor()
  get(): Promise<null>
  set(): Promise<void>
  del(): Promise<void>
  clear(): Promise<void>
}

declare class RedisCacheAdapter {
  constructor(redisCtx: RedisClientOptions, ttl?: number)
  connect(): Promise<RedisClientType>
  handleShutdown(): Promise<void>
  get(key: string): Promise<any>
  put(key: string, value: any): Promise<void>
  del(key: string): Promise<void>
  clear(): Promise<void>
  getAllKeys(): string[]
}

declare class LRUCacheAdapter {
  constructor(options?: { ttl?: number, maxSize?: number })
  get(key: string): any
  put(key: string, value: any, ttl?: number): void
  del(key: string): void
  clear(): void
}

declare namespace TestUtils {
  function destroyAllDataPermanently(fast?: boolean): Promise<void>

  interface ModifiledPromise<T> extends Promise<T> {
    resolve: Function
    reject: Function
  }

  function resolvingPromise(): ModifiledPromise<any>

  function sleep(ms: number): Promise<void>
}

export interface PushAdapter {
  /**
   * @param {any} body
   * @param {Parse.Installation[]} installations
   * @param {any} pushStatus
   * @returns {Promise}
   */
  send(body: any, installations: any[], pushStatus: any): Promise<any>

  /**
   * Get an array of valid push types.
   * @returns {Array} An array of valid push types
   */
  getValidPushTypes(): string[]
}

declare class PushWorker {
  subscriber?: any;
  adapter: any;
  channel: string;
  constructor(pushAdapter: PushAdapter, subscriberConfig?: any)
  run(options: any): Promise<any>
  sendToAdapter(
    body: any,
    installations: any[],
    pushStatus: any,
    config: Config,
    UTCOffset?: any
  ): Promise<any>
}

declare class ParseGraphQLServer {
  constructor(parseServer:ParseServer, config:{graphQLPath: string, graphQLCustomTypeDefs?:any[]})
  applyGraphQL(app:Express):void
  applyPlayground(app:Express):void
  createSubscriptions(server:any):void
  setGraphQLConfig(graphQLConfig: any): Promise<any>
}

declare namespace SchemaMigrations {
  interface SchemaOptions {
    definitions: JSONSchema[];
    strict?: boolean;
    deleteExtraFields?: boolean;
    recreateModifiedFields?: boolean;
    lockSchemas?: boolean;
    beforeMigration?: () => void | Promise<void>;
    afterMigration?: () => void | Promise<void>;
  }

  type FieldValueType =
  | 'String'
  | 'Boolean'
  | 'File'
  | 'Number'
  | 'Relation'
  | 'Pointer'
  | 'Date'
  | 'GeoPoint'
  | 'Polygon'
  | 'Array'
  | 'Object'
  | 'ACL';

  interface FieldType {
    type: FieldValueType;
    required?: boolean;
    defaultValue?: mixed;
    targetClass?: string;
  }

  type ClassNameType = '_User' | '_Role' | string;

  interface ProtectedFieldsInterface {
    [key: string]: string[];
  }

  interface IndexInterface {
    [key: string]: number;
  }
  
  interface IndexesInterface {
    [key: string]: IndexInterface;
  }
  
  type CLPOperation = 'find' | 'count' | 'get' | 'update' | 'create' | 'delete';
  
  interface CLPValue  { [key: string]: boolean }
  interface CLPData  { [key: string]: CLPOperation[] }
  interface CLPInterface  { [key: string]: CLPValue }

  interface JSONSchema {
    className: ClassNameType;
    fields?: { [key: string]: FieldType };
    indexes?: IndexesInterface;
    classLevelPermissions?: {
      find?: CLPValue,
      count?: CLPValue,
      get?: CLPValue,
      update?: CLPValue,
      create?: CLPValue,
      delete?: CLPValue,
      addField?: CLPValue,
      protectedFields?: ProtectedFieldsInterface,
    };
  }

  class CLP {
    static allow(perms: { [key: string]: CLPData }): CLPInterface
  }

  function makeSchema(className: ClassNameType, schema: JSONSchema): JSONSchema
}

export default ParseServer;
export {
  ParseServer,
  S3Adapter,
  GCSAdapter,
  InMemoryCacheAdapter,
  NullCacheAdapter,
  RedisCacheAdapter,
  LRUCacheAdapter,
  TestUtils,
  PushWorker,
  ParseGraphQLServer,
  SchemaMigrations,
  AuthAdapter,
  FileSystemAdapter
};
