import { Hono } from 'hono'
import { privateKeyToAccount } from "viem/accounts";
import { createNexusClient } from "@biconomy/sdk"; 
import { polygonAmoy } from "viem/chains"; 
import { http, parseEther } from "viem"; 

const app = new Hono()

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

const privateKey = "PRIVATE_KEY";
const account = privateKeyToAccount(`0x${privateKey}`)
const bundlerUrl = "https://bundler.biconomy.io/api/v3/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44"
 
app.get('/address/:handle', async (c) => {
  const handle = c.req.param("handle")

  const nexusClient = await createNexusClient({ 
    signer: account, 
    chain: polygonAmoy, 
    transport: http(), 
    bundlerTransport: http(bundlerUrl), 
});
const smartAccountAddress = await nexusClient.account.address; 
  // return c.json({ address: handle })
})

app.post('/deploy', (c) => {
  
})

app.post('/changeOwner',  (c) => {

})


 



export default app
