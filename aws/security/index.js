exports.handler = function(event, context, callback) {
    const modifier = event.authorizationToken.split("-")[0];
    const apiKey = event.authorizationToken.split("-")[1];
    switch (modifier.toLowerCase()) {
        case 'allow':
            callback(null, generatePolicy('user', 'Allow', event.methodArn, apiKey));
            break;
        case 'deny':
            callback(null, generatePolicy('user', 'Deny', event.methodArn, apiKey));
            break;
        case 'unauthorized':
            callback("Unauthorized");   // Return a 401 Unauthorized response
            break;
        default:
            callback("Error: Invalid token");
    }
};

const generatePolicy = function(principalId, effect, resource, apiKey) {
    const authResponse = {};

    authResponse.principalId = principalId;
    if (effect && resource) {
        const policyDocument = {};
        policyDocument.Version = '2012-10-17';
        policyDocument.Statement = [];
        const statementOne = {};
        statementOne.Action = 'execute-api:Invoke';
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }

    authResponse.usageIdentifierKey = apiKey;
    return authResponse;
};