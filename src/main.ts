import { Hono } from 'hono'
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { createBicoPaymasterClient, createNexusClient } from "@biconomy/sdk"; 
import { baseSepolia } from "viem/chains"; 
import { createPublicClient, encodeFunctionData, http, parseAbi, parseEther } from "viem"; 
// import { ENTRYPOINT_ADDRESS_V07 } from "permissionless"
// import { KERNEL_V3_1 } from "@zerodev/sdk/constants"
 
// const kernelVersion = KERNEL_V3_1
// const entryPoint = ENTRYPOINT_ADDRESS_V07

const app = new Hono()
 
app.get('/', (c) => {
  return c.text('Hello Hono!')
})


const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(`${privateKey}`)

const bundlerUrl = "https://bundler.biconomy.io/api/v3/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44";
const paymasterUrl = "https://paymaster.biconomy.io/api/v2/84532/F7wyL1clz.75a64804-3e97-41fa-ba1e-33e98c2cc703"; 
 

const TRANSFER_OWNERSHIP_ABI = parseAbi([
  'function transferOwnership(address newOwner) external'
])

const SMART_ACCOUNT_OWNER_ABI = parseAbi([
  'function smartAccountOwners(address account) view returns (address)'
])
const K1_VALIDATOR_ADDRESS = '0x00000004171351c442B202678c48D8AB5B321E8f'

async function getNexusClient(handle: string) {
  let index = ConvertToBn(handle)
  
  return await createNexusClient({ 
    signer: account, 
    chain: baseSepolia, 
    transport: http(), 
    index: index,
    bundlerTransport: http(bundlerUrl), 
    paymaster: createBicoPaymasterClient({paymasterUrl})
  });
}

function ConvertToBn(handle: string) {
  return BigInt(`0x${Buffer.from(handle).toString('hex')}`)
}

// console.log(ConvertToBn("fdadf14"));


app.get('/address/:handle', async (c) => {
  const handle = c.req.param("handle")
  const nexusClient = await getNexusClient(handle)

  return c.json({ address: await nexusClient.account.address })
})

app.post('/deploy', async (c) => {
  const {handle, newOwner} = await c.req.json()
  console.log("handle: ", handle, "newOwner: ", newOwner);
  
  const nexusClient = await getNexusClient(handle); 
  
  const hash0 = await nexusClient.sendTransaction({ calls:  
      [{to : '0xf5715961C550FC497832063a98eA34673ad7C816', value: parseEther('0')}] },
  );
  console.log("Transaction hash0: ", hash0) 
  await nexusClient.waitForTransactionReceipt({ hash: hash0 });

  const callData = encodeFunctionData({
    abi: TRANSFER_OWNERSHIP_ABI,
    functionName: 'transferOwnership',
    args: [newOwner as `0x${string}`]
  })

  console.log(K1_VALIDATOR_ADDRESS);
  const hash = await nexusClient.sendTransaction({
    calls: [{
      to: K1_VALIDATOR_ADDRESS,
      data: callData,
      value: parseEther('0')
    }]
  })

  console.log('Ownership transfer transaction hash:', hash)
  const receipt = await nexusClient.waitForTransactionReceipt({ hash })

  return c.json({ address: await nexusClient.account.address, hash })
})

app.get('/owners/:account', async (c) => {
  const account = c.req.param("account")

  const publicClient = createPublicClient({ 
    chain: baseSepolia,
    transport: http()
  })

  const owners = await publicClient.call({
    to: K1_VALIDATOR_ADDRESS,
    data: encodeFunctionData({
      abi: SMART_ACCOUNT_OWNER_ABI,
      functionName: 'smartAccountOwners',
      args: [account as `0x${string}`]
    })
  })

  return c.json({ owners })
})


// app.post('/test', async (c) => {
//   const privateKey = generatePrivateKey();
//   // console.log("privateKey: ", privateKey);
//   // const privateKey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
//   const account = privateKeyToAccount(`${privateKey}`);
   
//   const bundlerUrl = "https://bundler.biconomy.io/api/v3/84532/nJPK7B3ru.dd7f7861-190d-41bd-af80-6877f74b8f44";
//   const paymasterUrl = "https://paymaster.biconomy.io/api/v2/84532/F7wyL1clz.75a64804-3e97-41fa-ba1e-33e98c2cc703";
  
//   console.log("privateKey: ", privateKey);
  
//   const nexusClient = await createNexusClient({
//       signer: account,
//       chain: baseSepolia,
//       transport: http(),
//       bundlerTransport: http(bundlerUrl),
//       paymaster: createBicoPaymasterClient({paymasterUrl})
//   }); 
   
//   const hash = await nexusClient.sendTransaction({ calls:  
//       [{to : '0xf5715961C550FC497832063a98eA34673ad7C816', value: parseEther('0')}] },
//   ); 
//   console.log("Transaction hash: ", hash) 
//   const receipt = await nexusClient.waitForTransactionReceipt({ hash });
//   return c.json({ address: nexusClient.account.address, hash })
// })

export default app