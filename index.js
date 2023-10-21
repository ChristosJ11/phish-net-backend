
const fs = require('fs').promises;
const path = require('path');
const process = require('process');
const {authenticate} = require('@google-cloud/local-auth');
const {google} = require('googleapis');
const express = require('express')
const app = express()
const port = 3000
const x = require('dotenv').config();
const OpenAI = require('openai')

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
    // defaults to process.env["OPENAI_API_KEY"]
});

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/gpt', async (req, res) => {
    const messages = await authorize().then(listMessages)
    let bad_actors = new Set()

    for(let i=0; i<messages.length; i++){
        let sample_message = messages[i][1]
        let chatCompletion = await openai.chat.completions.create({
            messages: [{ role: 'system', content: "return a 1 if this is sounds like a phishing email or a 0 if it doesn't" },{ role: 'user', content: sample_message }],
            model: 'gpt-3.5-turbo',
          });
          if(chatCompletion.choices[0].message.content == '1'){
            bad_actors.add(messages[i][0])
          }
    }

    console.log(bad_actors)
    
    
     
  })

app.get('/categorize', async(req, res) => {
    
    messages = await authorize().then(listMessages)
    res = {
        financial: 0,
        password : 0,
        identity : 0,
        none : 0

    }
    console.log("The messages length is: " + messages.length)
    for(let i=0; i<messages.length; i++){
        let sample_message = messages[i][1]
        let chatCompletion = await openai.chat.completions.create({
            messages: [{ role: 'system', content: "return a 1 if this is sounds like a phishing email or a 0 if it doesn't" },{ role: 'user', content: sample_message }],
            model: 'gpt-3.5-turbo',
          });
          if(chatCompletion.choices[0].message.content == '0'){
            res.none+=1
          }else{
            chatCompletion = await openai.chat.completions.create({
                messages: [{ role: 'system', content: `return a 3 if this is sounds like an financial phishing email, 2 
                if this is sounds like an password phishing email, 1 if this is sounds like an identity phishing email, 
                only return one of these numbers, not any explanation` },
                { role: 'user', content: sample_message }],
                model: 'gpt-3.5-turbo',
              });
              console.log(chatCompletion.choices[0].message.content)
              if(chatCompletion.choices[0].message.content == '3'){
                res.financial+=1
              }else if(chatCompletion.choices[0].message.content == '2'){
                res.password+=1
              }
              else if(chatCompletion.choices[0].message.content == '1'){
                res.identity+=1
              }
          }

        
    }
    console.log(res)
    return res

  })

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
//   authorize().then(listMessages).catch(console.error);

})
// If modifying these scopes, delete token.json.
const SCOPES = ['https://mail.google.com/'];
// The file token.json stores the user's access and refresh tokens, and is
// created automatically when the authorization flow completes for the first
// time.
const TOKEN_PATH = path.join(process.cwd(), 'token.json');
const CREDENTIALS_PATH = path.join(process.cwd(), 'credentials.json');

/**
 * Reads previously authorized credentials from the save file.
 *
 * @return {Promise<OAuth2Client|null>}
 */
async function loadSavedCredentialsIfExist() {
  try {
    const content = await fs.readFile(TOKEN_PATH);
    const credentials = JSON.parse(content);
    return google.auth.fromJSON(credentials);
  } catch (err) {
    return null;
  }
}

/**
 * Serializes credentials to a file compatible with GoogleAUth.fromJSON.
 *
 * @param {OAuth2Client} client
 * @return {Promise<void>}
 */
async function saveCredentials(client) {
  const content = await fs.readFile(CREDENTIALS_PATH);
  const keys = JSON.parse(content);
  const key = keys.installed || keys.web;
  const payload = JSON.stringify({
    type: 'authorized_user',
    client_id: key.client_id,
    client_secret: key.client_secret,
    refresh_token: client.credentials.refresh_token,
  });
  await fs.writeFile(TOKEN_PATH, payload);
}

/**
 * Load or request or authorization to call APIs.
 *
 */
async function authorize() {
  let client = await loadSavedCredentialsIfExist();
  if (client) {
    return client;
  }
  client = await authenticate({
    scopes: SCOPES,
    keyfilePath: CREDENTIALS_PATH,
  });
  if (client.credentials) {
    await saveCredentials(client);
  }
  return client;
}

/**
 * Lists the labels in the user's account.
 *
 * @param {google.auth.OAuth2} auth An authorized OAuth2 client.
 */
async function listLabels(auth) {
  const gmail = google.gmail({version: 'v1', auth});
  const res = await gmail.users.labels.list({
    userId: 'me',
  });
  const labels = res.data.labels;
  if (!labels || labels.length === 0) {
    console.log('No labels found.');
    return;
  }
  console.log('Labels:');
  labels.forEach((label) => {
    console.log(`- ${label.name}`);
  });

  return auth
}

async function listMessages(auth){
    const NUM_RESULTS = 20
    const gmail = google.gmail({version: 'v1', auth});
    const res = await gmail.users.messages.list({
        userId: 'me',
        maxResults: NUM_RESULTS
      });
    const messages = res.data.messages
    console.log(messages.length)
    let count = 0
    let all_messages = []
    for(let i =0; i<NUM_RESULTS; i++){
       let  message = messages[i]
       current_message =  await getMessageBody(auth, message.id)
       if ( current_message.length > 1){
        all_messages.push(current_message)
       }
        count++
        console.log(count)
    }

    return all_messages
    // messages.forEach((message) => getMessageBody(auth, message.id));
}

async function getMessageBody(auth, id){
    const gmail = google.gmail({version: 'v1', auth});
  const res = await gmail.users.messages.get({
    userId: 'me',
    id:id
  });
  
  if( res.data.payload.parts != null && res.data.payload.parts[0].body.data != undefined){
      const encodeded_string = res.data.payload.parts[0].body.data
      const sender = res.data.payload.headers[6].value
      const buffer = Buffer.from(encodeded_string, 'base64');
      const decodedString = res.data.payload.headers[19].value + '\n' + buffer.toString('utf8');
      return [sender,decodedString]
    //   console.log(decodedString);
  }
  return ["sample"]
  
}

