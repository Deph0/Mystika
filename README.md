<h1 align="center">Mystika - Game Engine</h1>

<p align="center">
  <img src="../../blob/main/webserver/www/public/img/logo.png?raw=true">
</p>

<h3>Client Identity</h3>

<h5>Structure</h5>

```ts
declare interface Identity {
  id: string;
  useragent: string;
}
```

<h3>Packets</h3>

<h5>Types</h5>

```ts
const PacketTypes: PacketType = {
  0: "PING",
  1: "PONG",
  2: "CONNECTION_COUNT",
  3: "RATE_LIMITED",
  4: "LOGIN",
  5: "LOGIN_SUCCESS",
  6: "LOGIN_FAILED",
  7: "LOAD_MAP",
};
```

<h5>Structure</h5>

```ts
declare interface Packet {
  type: PacketType;
  data: PacketData;
  id: string | null;
  useragent: string | null;
}
```

<hr>
<h3>Rate Limiting</h3>
<h5>Options</h5>

```ts
const RateLimitOptions: RateLimitOptions = {
  maxRequests: 100,
  time: 5000,
  maxWindowTime: 4000,
};
```

<h5>Structure</h5>

```ts
declare interface RateLimitOptions {
  maxRequests: number;
  time: number;
  maxWindowTime: number;
}
```

<hr>
<h3>Events</h3>

```ts
import { Events } from "../socket/server";
```

<h5>Events.GetOnlineCount();</h5>
<p style="font-size:0.8em;">Returns the amount of clients that are currently connected</p>

<h5>Events.GetOnlineData();</h5>
<p style="font-size:0.8em;">Returns a list that contains client connection data</p>

<h5>Events.Broadcast(packet: string);</h5>
<p style="font-size:0.8em;">Broadcasts a message to all connected clients</p>

<h5>Events.GetClientRequests();</h5>
<p style="font-size:0.8em;">Returns a list that contains client request data

<h5>Events.GetRateLimitedClients();</h5>
<p style="font-size:0.8em;">Returns a list of rate limited clients</p>

<hr>
<h3>Listener Events</h3>

<h5>onAwake</h5>
<p style="font-size:0.8em;">Fires immediately after the server starts</p>

```ts
Listener.on("onAwake", (data) => {
  console.log("Awake event emitted");
});
```

<h5>onStart</h5>
<p style="font-size:0.8em;">Fires immediately after <b>onAwake</b></p>

```ts
Listener.on("onStart", (data) => {
  console.log("Start event emitted");
});
```

<h5>onUpdate</h5>
<p style="font-size:0.8em;">Fires immediately after <b>onStart</b> every 60 frames</p>

```ts
Listener.on("onUpdate", (data) => {
  console.log("Update event emitted");
});
```

<h5>onFixedUpdate</h5>
<p style="font-size:0.8em;">Fires immediately after <b>onStart</b> every 100ms</p>

```ts
Listener.on("onFixedUpdate", (data) => {
  console.log("Fixed update event emitted");
});
```

<h5>onSave</h5>
<p style="font-size:0.8em;">Runs every 5 minutes</p>

```ts
Listener.on("onSave", (data) => {
  console.log("Save event emitted");
});
```

<hr>
<h3>Inventory Management</h3>

```ts
import inventory from "../systems/inventory";
```

<h5>Structure</h5>

```ts
declare interface InventoryItem {
  name: string;
  quantity: number;
}
```

<h5>inventory.add();</h5>
<p style="font-size:0.8em;">Add an item to player inventory</p>

```ts
await inventory.add("user_name", { name: "item_name", quantity: number });
```

<h5>inventory.remove();</h5>
<p style="font-size:0.8em;">Remove an item from player inventory</p>

```ts
await inventory.remove("user_name", { name: "item_name", quantity: number });
```

<h5>inventory.find();</h5>
<p style="font-size:0.8em;">Find an item from player inventory</p>

```ts
await inventory.find("user_name", { name: "item_name" });
```

<h5>inventory.delete();</h5>
<p style="font-size:0.8em;">Delete an item from player inventory</p>

```ts
await inventory.delete("user_name", { name: "item_name" });
```

<hr>
<h3>Item Management</h3>

```ts
import items from "../systems/items";
```

<h5>Structure</h5>

```ts
declare interface Item {
  name: string;
  quality: string;
  description: string;
}
```

<h5>items.add();</h5>
<p style="font-size:0.8em;">Add an item to the item database</p>

```ts
await items.add({ name: "item_name", quality: "item_quality", description: "item_description" });
```

<h5>items.remove();</h5>
<p style="font-size:0.8em;">Remove an item from the item database</p>

```ts
await items.remove({ name: "item_name" });
```

<h5>items.list();</h5>
<p style="font-size:0.8em;">List all items from the item database</p>

```ts
await items.list();
```

<h5>items.find();</h5>
<p style="font-size:0.8em;">Find an item from the item database</p>

```ts
await items.find({ name: "item_name" });
```

<hr>