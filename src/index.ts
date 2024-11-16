import { Hono } from 'hono'
import { privateKeyToAccount } from "viem/accounts";
import { createNexusClient } from "@biconomy/sdk"; 
import { baseSepolia } from "viem/chains"; 
import { http, parseEther } from "viem"; 

const app = new Hono()

app.get('/', (c) => {
  return c.text('Hello Hono!')
})

const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(`${privateKey}`)
const bundlerUrl = "https://bundler.biconomy.io/api/v3/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44"

async function getNexusAddress(handle: string) {
  let index = ConvertToBn(handle)
  const nexusClient = await createNexusClient({ 
    signer: account, 
    chain: baseSepolia, 
    transport: http(), 
    index: index,
    bundlerTransport: http(bundlerUrl), 
  });
  // const smartAccountAddress = 
  return await nexusClient.account.address; 
}

function ConvertToBn(handle: string) {
  return BigInt(handle)
}

app.get('/address/:handle', async (c) => {
  const handle = c.req.param("handle")

  // return c.json({ address: await getNexusAddress(handle)
  return c.json({ address: handle })
})


app.post('/deploy', async (c) => {
  return c.json({ address: await getNexusAddress("111") })
  // TODO: 组 deploy , 发一笔空交易（或 changeOwner）
})

app.post('/changeOwner',  async (c) => {
  return c.json({ address: await getNexusAddress("111") })
  // TODO: 组 changeOwner 的逻辑
})

export default app