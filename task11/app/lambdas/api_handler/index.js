import AWS from 'aws-sdk';
import { v4 as uuidv4 } from 'uuid';

// Initialize AWS services
const dynamodb = new AWS.DynamoDB.DocumentClient();
const cognito = new AWS.CognitoIdentityServiceProvider();

// Environment variable configuration
const USER_POOL_ID = process.env.cup_id;
const CLIENT_ID = process.env.cup_client_id;
const TABLES_TABLE = process.env.tables_table;
const RESERVATIONS_TABLE = process.env.reservations_table;

// Handler function
export const handler = async (event, context) => {
  console.log("Event:", JSON.stringify({
    path: event.path,
    httpMethod: event.httpMethod,
    headers: event.headers?.Authorization,
    body: event.body
  }));

  try {
    const routes = {
      "POST /signup": handleSignup,
      "POST /signin": handleSignin,
      "GET /tables": handleGetTables,
      "POST /tables": handleCreateTable,
      "GET /tables/{tableId}": handleGetTableById,
      "GET /reservations": handleGetReservations,
      "POST /reservations": handleCreateReservation,
    };

    const routeKey = `${event.httpMethod} ${event.resource}`;
    const handlerFunction = routes[routeKey] || notFoundHandler;

    const response = await handlerFunction(event);
    return response;
  } catch (error) {
    console.error("Error:", error);
    return formatResponse(500, {
      message: "Internal Server Error",
      error: error.message,
    });
  }
};

// Utilities
function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'OPTIONS, POST, GET',
    'Content-Type': 'application/json',
  };
}

function formatResponse(statusCode, body) {
  return {
    statusCode,
    headers: corsHeaders(),
    body: JSON.stringify(body),
  };
}

function getUsernameFromToken(event) {
  try {
    const claims = event.requestContext?.authorizer?.claims;
    return claims?.['cognito:username'] || null;
  } catch (error) {
    console.error('Error extracting username from token:', error);
    return null;
  }
}

function notFoundHandler() {
  return formatResponse(404, { message: "Not Found" });
}

// Handlers
async function handleSignup(event) {
  try {
    const { firstName, lastName, email, password } = JSON.parse(event.body);

    // Input validation
    if (!firstName || !lastName || !email || !password) {
      return formatResponse(400, { error: "All fields are required." });
    }

    if (!validateEmail(email)) {
      return formatResponse(400, { error: "Invalid email format." });
    }

    if (!validatePassword(password)) {
      return formatResponse(400, { error: "Invalid password format." });
    }

    // Create user in Cognito
    await cognito.adminCreateUser({
      UserPoolId: USER_POOL_ID,
      Username: email,
      UserAttributes: [
        { Name: "given_name", Value: firstName },
        { Name: "family_name", Value: lastName },
        { Name: "email", Value: email },
        { Name: "email_verified", Value: "true" },
      ],
      TemporaryPassword: password,
      MessageAction: "SUPPRESS",
    }).promise();

    await cognito.adminSetUserPassword({
      UserPoolId: USER_POOL_ID,
      Username: email,
      Password: password,
      Permanent: true,
    }).promise();

    return formatResponse(200, { message: "User created successfully." });
  } catch (error) {
    console.error("Signup error:", error);
    return formatResponse(error.code === "UsernameExistsException" ? 400 : 502, {
      error: error.code === "UsernameExistsException" ? "Email already exists." : "Signup failed.",
    });
  }
}

async function handleSignin(event) {
  try {
    const { email, password } = JSON.parse(event.body);

    const params = {
      AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
      UserPoolId: USER_POOL_ID,
      ClientId: CLIENT_ID,
      AuthParameters: { USERNAME: email, PASSWORD: password },
    };

    const authResponse = await cognito.adminInitiateAuth(params).promise();
    const authResult = authResponse.AuthenticationResult;

    if (!authResult) {
      return formatResponse(400, { error: "Authentication failed. Try again." });
    }

    return formatResponse(200, { idToken: authResult.IdToken });
  } catch (error) {
    console.error("Sign-in error:", error);
    return formatResponse(400, {
      error: error.code === "NotAuthorizedException" ? "Invalid email or password." : "Authentication failed.",
    });
  }
}

async function handleGetTables(event) {
  const username = getUsernameFromToken(event);
  if (!username) return formatResponse(401, { message: "Unauthorized" });

  try {
    const result = await dynamodb.scan({ TableName: TABLES_TABLE }).promise();
    const tables = result.Items.map(({ id, number, places, isVip, minOrder }) => ({
      id: Number(id), number, places, isVip, minOrder: minOrder || 0,
    }));

    return formatResponse(200, { tables });
  } catch (error) {
    console.error("Error fetching tables:", error);
    return formatResponse(500, { message: "Internal Server Error" });
  }
}

async function handleCreateTable(event) {
  const username = getUsernameFromToken(event);
  if (!username) return formatResponse(401, { message: 'Unauthorized' });

  const table = JSON.parse(event.body);
  const { number, places, isVip, minOrder } = table;

  if (typeof number !== "number" || typeof places !== "number" || typeof isVip !== "boolean") {
    return formatResponse(400, { message: 'Invalid table data.' });
  }

  const tableId = table.id || uuidv4();
  const tableData = { id: String(tableId), number, places, isVip, minOrder: minOrder || 0 };

  try {
    await dynamodb.put({ TableName: TABLES_TABLE, Item: tableData }).promise();
    return formatResponse(200, { id: tableId });
  } catch (error) {
    console.error("Error creating table:", error);
    return formatResponse(500, { message: "Internal Server Error" });
  }
}

async function handleGetTableById(event) {
  const username = getUsernameFromToken(event);
  if (!username) return formatResponse(401, { message: "Unauthorized" });

  const tableId = event.pathParameters?.tableId;

  try {
    const result = await dynamodb.get({ TableName: TABLES_TABLE, Key: { id: tableId } }).promise();
    if (!result.Item) return formatResponse(404, { message: "Table not found" });

    const { id, number, places, isVip, minOrder } = result.Item;
    return formatResponse(200, { id: Number(id), number, places, isVip, minOrder: minOrder || 0 });
  } catch (error) {
    console.error("Error fetching table by ID:", error);
    return formatResponse(500, { message: "Internal Server Error" });
  }
}

async function handleGetReservations(event) {
  const username = getUsernameFromToken(event);
  if (!username) return formatResponse(401, { message: "Unauthorized" });

  const queryParams = event.queryStringParameters || {};
  const params = { TableName: RESERVATIONS_TABLE };

  if (queryParams.user) {
    params.FilterExpression = "username = :username";
    params.ExpressionAttributeValues = { ":username": queryParams.user };
  }

  try {
    const result = await dynamodb.scan(params).promise();
    const reservations = result.Items.map(item => ({
      tableNumber: item.tableNumber,
      clientName: item.clientName,
      phoneNumber: item.phoneNumber,
      date: item.date,
      slotTimeStart: item.time,
      slotTimeEnd: item.slotTimeEnd,
    }));

    return formatResponse(200, { reservations });
  } catch (error) {
    console.error("Error fetching reservations:", error);
    return formatResponse(500, { message: "Internal Server Error" });
  }
}

async function handleCreateReservation(event) {
  const username = getUsernameFromToken(event);
  if (!username) return formatResponse(401, { message: "Unauthorized" });

  const { tableNumber, clientName, phoneNumber, date, slotTimeStart, slotTimeEnd } = JSON.parse(event.body);

  if (!tableNumber || !date || !slotTimeStart || !slotTimeEnd) {
    return formatResponse(400, { message: 'Missing required fields.' });
  }

  try {
    const tableResult = await dynamodb.scan({
      TableName: TABLES_TABLE,
      FilterExpression: "#num = :tableNumber",
      ExpressionAttributeNames: { "#num": "number" },
      ExpressionAttributeValues: { ":tableNumber": tableNumber },
    }).promise();

    if (tableResult.Items.length === 0) {
      return formatResponse(400, { message: 'Table not found' });
    }

    const table = tableResult.Items[0];
    const tableId = table.id;

    const existingReservations = await dynamodb.scan({
      TableName: RESERVATIONS_TABLE,
      FilterExpression: "tableId = :tableId AND #date = :date AND (#time BETWEEN :start AND :end OR :start BETWEEN #time AND slotTimeEnd)",
      ExpressionAttributeNames: { "#date": "date", "#time": "time" },
      ExpressionAttributeValues: { ":tableId": tableId, ":date": date, ":start": slotTimeStart, ":end": slotTimeEnd },
    }).promise();

    if (existingReservations.Items.length > 0) {
      return formatResponse(400, { message: 'Table already reserved for the selected time.' });
    }

    const reservation = {
      id: uuidv4(),
      tableId,
      tableNumber: table.number,
      clientName,
      phoneNumber,
      username,
      date,
      time: slotTimeStart,
      slotTimeEnd,
      createdAt: new Date().toISOString(),
    };

    await dynamodb.put({ TableName: RESERVATIONS_TABLE, Item: reservation }).promise();
    return formatResponse(200, { reservationId: reservation.id, message: 'Reservation created successfully.' });
  } catch (error) {
    console.error("Error creating reservation:", error);
    return formatResponse(500, { message: "Internal Server Error" });
  }
}

// Validation functions
function validateEmail(email) {
  const regex = /^[\w.%+-]+@[\w.-]+\.[a-zA-Z]{2,}$/;
  return regex.test(email);
}

function validatePassword(password) {
  const regex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[$%^*-_])[A-Za-z\d$%^*-_]{12,}$/;
  return regex.test(password);
}