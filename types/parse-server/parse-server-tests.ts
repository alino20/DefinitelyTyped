// import ParseServer from 'parse-server';
async function test_import() {
    const module = await import('parse-server');

    const ParseServer = module.default;
    const parseServer = new ParseServer({
        databaseURI: 'mongodb://localhost:27017/dev',
        cloud: __dirname + '/cloud/main.js',
        appId: 'myAppId',
        masterKey: 'myMasterKey', //Add your master key here. Keep it secret!
        serverURL: 'XXXXXXXXXXXXXXXXXXXXXXXXXXX' // Don't forget to change to https if needed
    });

    ParseServer.startApp({
        databaseURI: 'mongodb://localhost:27017/dev',
        cloud: __dirname + '/cloud/main.js',
        appId: 'myAppId',
        masterKey: 'myMasterKey', //Add your master key here. Keep it secret!
        serverURL: 'XXXXXXXXXXXXXXXXXXXXXXXXXXX' // Don't forget to change to https if needed
    })


    const { AuthAdapter,
        FileSystemAdapter,
        InMemoryCacheAdapter,
        LRUCacheAdapter,
        NullCacheAdapter,
        ParseGraphQLServer,
        PushWorker,RedisCacheAdapter } = module

    new AuthAdapter()
    FileSystemAdapter()
    new InMemoryCacheAdapter({})
    new LRUCacheAdapter()
    new NullCacheAdapter()
    new ParseGraphQLServer(parseServer, {
        graphQLPath: '/graphql'
    })
    new PushWorker({
        getValidPushTypes: () => ['ios', 'android'],
        send: async (data, []) => {
            console.log(data)
        }
    })
    new RedisCacheAdapter({}),
    module.SchemaMigrations.makeSchema('MyClass', {
        className: 'MyClass'
    })
    module.TestUtils.destroyAllDataPermanently();
    module.TestUtils.destroyAllDataPermanently(true);
}
