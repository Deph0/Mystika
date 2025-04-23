const socket = new WebSocket(`__VAR.WEBSOCKETURL__`);
import * as pako from "../libs/pako.js";
socket.binaryType = "arraybuffer";
const players = [] as any[];
const npcs = [] as any[];
const mapScale = 0.1;
const audioCache = new Map<string, string>();
const npcImage = new Image();
npcImage.src = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACMAAAAmCAYAAABOFCLqAAABhGlDQ1BJQ0MgcHJvZmlsZQAAKJF9kT1Iw0AcxV9TxQ8qDq0g4pChioNdVMSxVLEIFkpboVUHk0u/oElDkuLiKLgWHPxYrDq4OOvq4CoIgh8g7oKToouU+L+k0CLGg+N+vLv3uHsHCI0KU82uKKBqlpGKx8RsblXseYWAPgQxgSGJmXoivZiB5/i6h4+vdxGe5X3uzzGg5E0G+ETiKNMNi3iDeHbT0jnvE4dYSVKIz4knDbog8SPXZZffOBcdFnhmyMik5olDxGKxg+UOZiVDJZ4hDiuqRvlC1mWF8xZntVJjrXvyFwby2kqa6zRHEccSEkhChIwayqjAQoRWjRQTKdqPefhHHH+SXDK5ymDkWEAVKiTHD/4Hv7s1C9NTblIgBnS/2PbHGNCzCzTrtv19bNvNE8D/DFxpbX+1Acx9kl5va+EjYHAbuLhua/IecLkDDD/pkiE5kp+mUCgA72f0TTkgeAv0r7m9tfZx+gBkqKvlG+DgEBgvUva6x7t7O3v790yrvx+jlHK64ZQ6gAAAAAZiS0dEAAAAAAAA+UO7fwAAAAlwSFlzAAAuIwAALiMBeKU/dgAAAAd0SU1FB+kCCRMwEsjIppIAAAAZdEVYdENvbW1lbnQAQ3JlYXRlZCB3aXRoIEdJTVBXgQ4XAAAB50lEQVRYw+2YvWvCYBDGn7xk0yRUKtqIiBBaUAoOznXv6B9b6GhnN3GRDErQRG2U1w9cStNB35hEjV/5sOBNuYRcft7de88h95LPW7gR4wHg/fURkrCMDYLOE/hofYMAgCQsQeeJ2EBYIgi7OS5UMS3VI4Oi8wSmpTrGhaq7TACgTBpQUYOyyZIkLJESg2+nyYyz46uGCWXS2IVhQKxsfSqhT7fPkuTHvl788mf7TstJ1PU9ZsTvVyTJjyvoNXZKLN7vZfuEOZrsat+nJwluyO4w/wKGPzaY9l0H4Z8MQ72nIUQJ2FsmNVWz5SBs0WRaOC3VoaZquzDpXhOmYUam3pKwhGmYSPea7jKxbEie8Ry2KZMGILB+Wq1hirlFrKcoJS6A1iYzn+0HyGJ8C99gxgHQ1z0ji9bmRjwgLBF2A8uihVWxgg6XiQSiw2WwKlZcFXFNYK2rI0lHkcAk6QhaVz889J6tISC6Uxdqaazh8Qksixa+2sb2COafrgZQtW0W3srZ87UpCAhvLCfUWTCsVN6yXeOrl6wQQWbl1Lj35eoOE9jaqWo64Gg2r3Zd6quaDvmcOTOYcZvBFPwUlsvZgxOe+KloWHZoSyB+Kho2kHdLIH4qGrZ5twTeT0XDNueWAADcLf3B+AfAy/vU2Mt7LwAAAABJRU5ErkJggg==';
const onlinecount = document.getElementById("onlinecount") as HTMLDivElement;
const canvas = document.getElementById("game") as HTMLCanvasElement;
const ctx = canvas.getContext("2d");
const playerCanvas = document.getElementById("players") as HTMLCanvasElement;
const npcCanvas = document.getElementById("npcs") as HTMLCanvasElement;
const npcContext = npcCanvas.getContext("2d");
const gameContext = playerCanvas.getContext("2d");
const progressBar = document.getElementById("progress-bar") as HTMLDivElement;
const progressBarContainer = document.getElementById("progress-bar-container") as HTMLDivElement;
const currentPlayerCanvas = document.getElementById(
  "current-player"
) as HTMLCanvasElement;
const currentgameContext = currentPlayerCanvas.getContext("2d");
const inventoryUI = document.getElementById("inventory") as HTMLDivElement;
const inventoryGrid = document.getElementById("grid") as HTMLDivElement;
const statUI = document.getElementById("stat-screen") as HTMLDivElement;
const chatInput = document.getElementById("chat-input") as HTMLInputElement;
const startGameButton = document.getElementById("start-game-button") as HTMLButtonElement;
const loadingScreen = document.getElementById("loading-screen");
if (startGameButton) {
  startGameButton.addEventListener("click", () => {
    socket.send(
      packet.encode(
        JSON.stringify({
          type: "STARTGAME",
          data: null,
        })
      )
    );
    // Hide the start game button
    startGameButton.style.display = "none";
    // Hide the loading screen
    if (loadingScreen) {
      // Fade out the loading screen after the map is loaded
      loadingScreen.style.transition = "1s";
      loadingScreen.style.opacity = "0";
      setTimeout(() => {
        loadingScreen.style.display = "none";
        progressBar.style.width = "0%";
        progressBarContainer.style.display = "block";
      }, 1000);
    }
  });
}
const healthBar = document.getElementById(
  "health-progress-bar"
) as HTMLDivElement;
const staminaBar = document.getElementById(
  "stamina-progress-bar"
) as HTMLDivElement;
const targetStats = document.getElementById(
  "target-stats-container"
) as HTMLDivElement;
const targetHealthBar = document.getElementById(
  "target-health-progress-bar"
) as HTMLDivElement;
const targetStaminaBar = document.getElementById(
  "target-stamina-progress-bar"
) as HTMLDivElement;
//const map = document.getElementById("map") as HTMLDivElement;
const fullmap = document.getElementById("full-map") as HTMLDivElement;
//const mapPosition = document.getElementById("position") as HTMLDivElement;
const pauseMenu = document.getElementById(
  "pause-menu-container"
) as HTMLDivElement;
const optionsMenu = document.getElementById(
  "options-menu-container"
) as HTMLDivElement;
const menuElements = ["options-menu-container"];
const fpsSlider = document.getElementById("fps-slider") as HTMLInputElement;
const musicSlider = document.getElementById("music-slider") as HTMLInputElement;
const effectsSlider = document.getElementById(
  "effects-slider"
) as HTMLInputElement;
const mutedCheckbox = document.getElementById(
  "muted-checkbox"
) as HTMLInputElement;
const healthLabel = document.getElementById("stats-screen-health-label") as HTMLDivElement;
const manaLabel = document.getElementById("stats-screen-mana-label") as HTMLDivElement;
let loaded: boolean = false;
let toggleInventory = false;
const times = [] as number[];
let lastFrameTime = 0; // Track the time of the last frame
let controllerConnected = false;

// Add these variables near the top with other declarations
let cameraX = 0;
let cameraY = 0;
const cameraSmoothing = 0.1; // Adjust between 0 and 1 (lower = smoother but slower)

// Add this variable with other declarations at the top
let lastSentDirection = "";

function lerp(start: number, end: number, amount: number) {
  return start + (end - start) * amount;
}

function updateCamera() {
  if (!loaded) return;
  
  const currentPlayer = players.find(
    (player) => player.id === sessionStorage.getItem("connectionId")
  );
  
  if (currentPlayer) {
    // Calculate target camera position
    const targetX = currentPlayer.position.x - window.innerWidth / 2 + 8;
    const targetY = currentPlayer.position.y - window.innerHeight / 2 + 48;
    
    // Smoothly interpolate camera position
    cameraX = lerp(cameraX, targetX, cameraSmoothing);
    cameraY = lerp(cameraY, targetY, cameraSmoothing);
    
    // Apply camera position
    window.scrollTo(cameraX, cameraY);
  }
  
  // Request next frame
  requestAnimationFrame(updateCamera);
}

// Start camera updates
updateCamera();

// Event listener for gamepad connection
window.addEventListener("gamepadconnected", () => {
  controllerConnected = true;
});

// Event listener for gamepad disconnection
window.addEventListener("gamepaddisconnected", () => {
  controllerConnected = false;
});

const packet = {
  decode(data: ArrayBuffer) {
    const decoder = new TextDecoder();
    return decoder.decode(data);
  },
  encode(data: string) {
    const encoder = new TextEncoder();
    return encoder.encode(data);
  },
};

function npcAnimationLoop() {
  if (!npcContext || !npcCanvas) return;
  npcContext.clearRect(0, 0, npcCanvas.width, npcCanvas.height);
  npcs.forEach((npc) => {
    npc.show(npcContext);
    npc.particles.forEach((particle: Particle) => {
      npc.updateParticle(particle, npc, npcContext);
    });
  });
  window.requestAnimationFrame(npcAnimationLoop);
}

function animationLoop() {
  if (!ctx || !gameContext) return;

  // Get the desired frame rate from the slider
  const fpsTarget = parseFloat(fpsSlider.value); // Convert to a number if needed
  const frameDuration = 1000 / fpsTarget; // Duration of each frame in milliseconds

  // Get the current time
  const now = performance.now();

  // If enough time has passed since the last frame, proceed
  if (now - lastFrameTime >= frameDuration) {
    lastFrameTime = now;

    // Clear the canvas
    gameContext.clearRect(0, 0, playerCanvas.width, playerCanvas.height);

    const currentPlayer = players.find(
      (player) => player.id === sessionStorage.getItem("connectionId")
    );
    // All players except the current player
    players.forEach((player) => {
      if (player.id !== sessionStorage.getItem("connectionId")) {
        if (player.isStealth) {
          if (currentPlayer) {
            if (currentPlayer.isAdmin) {
              player.show(gameContext);
            }
          }
        } else {
          player.show(gameContext);
        }
      }
    });

    // Calculate FPS
    while (times.length > 0 && times[0] <= now - 1000) {
      times.shift();
    }
    times.push(now);
  }

  // Request the next frame
  window.requestAnimationFrame(animationLoop);
}

function currentPlayerLoop() {
  if (!ctx || !currentgameContext) return;
  currentgameContext.clearRect(
    0,
    0,
    currentPlayerCanvas.width,
    currentPlayerCanvas.height
  );
  players.forEach((player) => {
    if (player.id === sessionStorage.getItem("connectionId")) {
      player.show(currentgameContext);
    }
  });


  window.requestAnimationFrame(currentPlayerLoop);
}

// Start the animation loops
animationLoop();
currentPlayerLoop();
npcAnimationLoop();

// Event listener for joystick movement
window.addEventListener("gamepadjoystick", (e: CustomEventInit) => {
  if (!loaded) return;
  if (pauseMenu.style.display == "block") return;

  // Get the joystick coordinates
  const x = e.detail.x;
  const y = e.detail.y;

  // Check if joystick is in neutral position (increased deadzone)
  const deadzone = 0.5;
  if (Math.abs(x) < deadzone && Math.abs(y) < deadzone) {
    if (lastSentDirection !== "ABORT") {
      socket.send(
        packet.encode(
          JSON.stringify({
            type: "MOVEXY",
            data: "ABORT",
          })
        )
      );
      lastSentDirection = "ABORT";
    }
    return;
  }

  // Determine the angle in degrees
  const angle = Math.atan2(y, x) * (180 / Math.PI);

  // Determine direction based on angle ranges
  let direction = "";
  if (angle >= -22.5 && angle < 22.5) {
    direction = "RIGHT";
  } else if (angle >= 22.5 && angle < 67.5) {
    direction = "DOWNRIGHT";
  } else if (angle >= 67.5 && angle < 112.5) {
    direction = "DOWN";
  } else if (angle >= 112.5 && angle < 157.5) {
    direction = "DOWNLEFT";
  } else if (angle >= 157.5 || angle < -157.5) {
    direction = "LEFT";
  } else if (angle >= -157.5 && angle < -112.5) {
    direction = "UPLEFT";
  } else if (angle >= -112.5 && angle < -67.5) {
    direction = "UP";
  } else if (angle >= -67.5 && angle < -22.5) {
    direction = "UPRIGHT";
  }

  // Only send if direction changed
  if (direction && direction !== lastSentDirection) {
    if (pauseMenu.style.display == "block") return;
    socket.send(
      packet.encode(
        JSON.stringify({
          type: "MOVEXY",
          data: direction,
        })
      )
    );
    lastSentDirection = direction;
  }
});

socket.onopen = () => {
  const _packet = {
    type: "PING",
    data: null,
  };
  socket.send(packet.encode(JSON.stringify(_packet)));
};

socket.onclose = () => {
  // Remove the loading bar if it exists
  progressBarContainer.style.display = 'none';
  showNotification("You have been disconnected from the server", false, true);
};

socket.onerror = () => {
  progressBarContainer.style.display = 'none';
  showNotification("An error occurred while connecting to the server", false, true);
};

socket.onmessage = async (event) => {
  if (!(event.data instanceof ArrayBuffer)) return;
  const data = JSON.parse(packet.decode(event.data))["data"];
  const type = JSON.parse(packet.decode(event.data))["type"];
  switch (type) {
    case "PONG":
      socket.send(packet.encode(JSON.stringify({ type: "LOGIN", data: null })));
      break;

    case "TIME_SYNC": {
      setTimeout(async () => {
        socket.send(
          packet.encode(
            JSON.stringify({
              type: "TIME_SYNC",
              data: data,
            })
          )
        );
      }, 5000);
      break;
    }
    case "CONNECTION_COUNT": {
      onlinecount.innerText = `${data} online`;
      break;
    }
    case "SPAWN_PLAYER": {
      await isLoaded();
      createPlayer(data);
      break;
    }
    case "LOAD_PLAYERS": {
      await isLoaded();
      if (!data) return;
      data.forEach((player: any) => {
        if (player.id != sessionStorage.getItem("connectionId")) {
          // Check if the player is already created and remove it
          players.forEach((p, index) => {
            if (p.id === player.id) {
              players.splice(index, 1);
            }
          });
          createPlayer(player);
        }
      });
      break;
    }
    case "DISCONNECT_PLAYER": {
      console.log("Player disconnected: " + data);
      // Remove the player from the players array
      players.forEach((player, index) => {
        if (player.id === data) {
          players.splice(index, 1);
          const dot = document.querySelector(`[data-id="${player.id}"]`) as HTMLElement;
          if (dot) {
            dot.remove();
          }
        }
        // Untarget the player if they are targeted
        if (player.targeted) {
          player.targeted = false;
          targetStats.style.display = "none";
          updateTargetStats(0, 0);
        }
      });

      break;
    }
    case "MOVEXY": {
      const player = players.find((player) => player.id === data.id);
      if (!player) return;

      // Handle movement abort
      if (data._data === "abort") {
        // Stop any ongoing movement animations/updates for this player
        break;
      }

      player.position.x = playerCanvas.width / 2 + data._data.x;
      player.position.y = playerCanvas.height / 2 + data._data.y;
      // If the player is the client, scroll to the player's position
      if (data.id == sessionStorage.getItem("connectionId")) {
        window.scrollTo(
          player.position.x - window.innerWidth / 2 + 8,
          player.position.y - window.innerHeight / 2 + 48
        );
        if (fullmap.style.display === "block") {
          if (player.id === sessionStorage.getItem("connectionId")) {
            const dot = document.getElementsByClassName("self")[0] as HTMLDivElement;
            if (dot) {
              dot.style.left = `${player.position.x * mapScale}px`;
              dot.style.top = `${player.position.y * mapScale}px`;
            }
          }
        }
      } else {
        if (fullmap.style.display === "block") {
          const dot = document.querySelector(`[data-id="${player.id}"]`) as HTMLElement;
          if (dot) {
            dot.style.left = `${player.position.x * mapScale}px`;
            dot.style.top = `${player.position.y * mapScale}px`;
          }
        }
      }
      break;
    }
    case "CREATE_NPC": {
      await isLoaded();
      if (!data) return;
      createNPC(data);
      break;
    }
    case "LOAD_MAP":
      {
        // Remove the full map image if it exists to update the map image with a new one
        const image = fullmap.querySelector("img") as HTMLImageElement;
        if (image) {
          fullmap.removeChild(image);
        }
        // Uncompress zlib compressed data
        // @ts-expect-error - pako is not defined because it is loaded in the index.html
        const inflated = pako.inflate(new Uint8Array(new Uint8Array(data[0].data)), { to: "string" });
        const mapData = inflated ? JSON.parse(inflated) : null;
        const mapHash = data[1] as string;
        const mapName = data[2];

        const fetchMap = async () => {
          const response = await fetch(`/map/hash?name=${mapName}`);
          if (!response.ok) {
            throw new Error("Failed to fetch map");
          }
          return response.json();
        };

        const serverMapHashResponse = await fetchMap();
        const serverMapHashData = serverMapHashResponse.hash;

        if (!serverMapHashData) {
          throw new Error("No map hash data found");
        }

        if (serverMapHashData !== mapHash) {
          throw new Error("Map hash mismatch");
        }

        const tilesets = mapData.tilesets;
        if (!tilesets) {
          throw new Error("No tilesets found");
        }

        const fetchTilesetImages = async () => {
          const fetchPromises = tilesets.map(async (tileset: any) => {
            const name = tileset.image.split("/").pop();
            const response = await fetch(`/tileset?name=${name}`);
            if (!response.ok) {
              throw new Error(`Failed to fetch tileset image: ${name}`);
            }
            const data = await response.json();
            return data;
          });

          return Promise.all(fetchPromises);
        };

        const result = await fetchTilesetImages();
        if (result.length === 0) {
          throw new Error("No tileset images found");
        }

        const images = [] as string[];
        for (const r of result) {
          const response = await fetch(`/tileset/hash?name=${r.tileset.name}`);
          if (!response.ok) {
            throw new Error("Failed to fetch tileset hash");
          }
          const data = await response.json();

          if (data.hash !== r.tileset.hash) {
            throw new Error("Tileset hash mismatch");
          }

          const image = new Image();
          // Uncompress zlib compressed data
          // @ts-expect-error - pako is not defined because it is loaded in the index.html
          const inflatedTilesetData = pako.inflate(new Uint8Array(r.tileset.data.data), { to: "string" });
          image.src = `data:image/png;base64,${inflatedTilesetData}`;
          await new Promise((resolve) => {
            image.onload = () => resolve(true);
          });
          images.push(image as unknown as string);
        }

        async function drawMap(images: string[]): Promise<void> {
          canvas.width = mapData.width * mapData.tilewidth;
          canvas.height = mapData.height * mapData.tileheight;
        
          playerCanvas.width = mapData.width * mapData.tilewidth;
          playerCanvas.height = mapData.height * mapData.tileheight;
        
          currentPlayerCanvas.width = playerCanvas.width;
          currentPlayerCanvas.height = playerCanvas.height;
        
          canvas.style.width = mapData.width * mapData.tilewidth + "px";
          canvas.style.height = mapData.height * mapData.tilewidth + "px";
        
          playerCanvas.style.width = mapData.width * mapData.tilewidth + "px";
          playerCanvas.style.height = mapData.height * mapData.tilewidth + "px";
        
          currentPlayerCanvas.style.width = playerCanvas.style.width;
          currentPlayerCanvas.style.height = playerCanvas.style.height;

          npcCanvas.width = mapData.width * mapData.tilewidth;
          npcCanvas.height = mapData.height * mapData.tileheight;

          npcCanvas.style.width = mapData.width * mapData.tilewidth + "px";
          npcCanvas.style.height = mapData.height * mapData.tilewidth + "px";
        
          if (!ctx) return;
          ctx.imageSmoothingEnabled = false;
        
          interface Layer {
            data: number[];
            zIndex?: number;
          }
        
          interface Tileset {
            firstgid: number;
            tilecount: number;
            imagewidth: number;
            tilewidth: number;
            tileheight: number;
          }
        
          const layers: Layer[] = mapData.layers;
        
          // Sort layers by 'zIndex' or default order
          const sortedLayers = [...layers].sort((a, b) => (a.zIndex || 0) - (b.zIndex || 0));
          let currentLayer = 0;
          let progress = 0;
          const step = 100 / layers.length;
        
          async function processLayer(layer: Layer): Promise<void> {
            const batchSize = 10; // Adjust for performance
            progress += step;
            progressBar.style.width = `${progress}%`;
        
            async function processRowBatch(startY: number): Promise<void> {
              for (let y = startY; y < startY + batchSize && y < mapData.height; y++) {
                for (let x = 0; x < mapData.width; x++) {
                  const tileIndex = layer.data[y * mapData.width + x];
                  if (tileIndex === 0) continue; // Skip empty tiles
        
                  // Find the correct tileset for the tileIndex
                  const tileset = tilesets.find(
                    (t: Tileset) => t.firstgid <= tileIndex && tileIndex < t.firstgid + t.tilecount
                  );
                  if (!tileset) continue;
        
                  const image = images[tilesets.indexOf(tileset)] as unknown as HTMLImageElement;
                  if (!image) continue;
        
                  // Calculate tile position within the tileset
                  const localTileIndex = tileIndex - tileset.firstgid;
                  const tilesPerRow = Math.floor(tileset.imagewidth / tileset.tilewidth);
                  const tileX = (localTileIndex % tilesPerRow) * tileset.tilewidth;
                  const tileY = Math.floor(localTileIndex / tilesPerRow) * tileset.tileheight;
        
                  // Calculate tile position on the canvas
                  const drawX = x * mapData.tilewidth;
                  const drawY = y * mapData.tileheight;
        
                  if (!ctx) return;
        
                  ctx.drawImage(
                    image,
                    tileX,
                    tileY,
                    tileset.tilewidth,
                    tileset.tileheight,
                    drawX,
                    drawY,
                    mapData.tilewidth,
                    mapData.tileheight
                  );
                }
              }
        
              // Process next batch of rows
              if (startY + batchSize < mapData.height) {
                await new Promise((resolve) => setTimeout(resolve, 0));
                await processRowBatch(startY + batchSize);
              }
            }
        
            await processRowBatch(0);
          }
        
          async function renderLayers(): Promise<void> {
            while (currentLayer < sortedLayers.length) {
              const layer = sortedLayers[currentLayer];
              await processLayer(layer);
              currentLayer++;
        
              // Update the canvas display after rendering each layer
              await new Promise((resolve) => requestAnimationFrame(resolve));
            }
        
            // Once all layers are drawn, start the animation loop
            canvas.style.display = "block";
            animationLoop();
            // Show the start game button
            startGameButton.style.display = "block";
            // Hide the progress bar
            progressBarContainer.style.display = "none";
            updateFullMap();
          }
        
          loaded = true;
          await renderLayers();
        }        

        await drawMap(images);
      }
      break;
    case "LOGIN_SUCCESS":
      {
        const connectionId = JSON.parse(packet.decode(event.data))["data"];
        const publicKey = JSON.parse(packet.decode(event.data))["publicKey"];
        sessionStorage.setItem("connectionId", connectionId); // Store client's socket ID
        const sessionToken = getCookie("token");
        if (!sessionToken) {
          window.location.href = "/";
          return;
        }

        // Store public key
        sessionStorage.setItem("publicKey", publicKey);

        const language = navigator.language.split("-")[0] || navigator.language || "en";
        socket.send(
          packet.encode(JSON.stringify({ type: "AUTH", data: sessionToken, language }))
        );
      }
      break;
    case "LOGIN_FAILED":
      {
        window.location.href = "/";
      }
      break;
    case "INVENTORY":
      {
        const data = JSON.parse(packet.decode(event.data))["data"];
        const slots = JSON.parse(packet.decode(event.data))["slots"];
        if (data.length > 0) {
          // Assign each item to a slot
          for (let i = 0; i < data.length; i++) {
            // Create a new item slot
            const slot = document.createElement("div");
            slot.classList.add("slot");
            slot.classList.add("ui");
            const item = data[i];
            slot.classList.add(item.quality.toLowerCase() || "empty");
            slot.innerHTML = `${item.item}${
              item.quantity > 1 ? `<br>x${item.quantity}` : ""
            }`;
            inventoryGrid.appendChild(slot);
          }
        }

        for (let i = 0; i < slots - data.length; i++) {
          const slot = document.createElement("div");
          slot.classList.add("slot");
          slot.classList.add("empty");
          slot.classList.add("ui");
          inventoryGrid.appendChild(slot);
        }
      }
      break;
    case "QUESTLOG": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      console.log(data);
      break;
    }
    case "QUESTDETAILS": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      console.log(data);
      break;
    }
    case "CHAT": {
      players.forEach((player) => {
        if (player.id === data.id) {
          player.chat = data.message;
        }
      });
      break;
    }
    case "NPCDIALOG": {
      const npc = npcs.find((npc) => npc.id === data.id);
      if (!npc) return;
      npc.dialog = data.dialog;
      break;
    }
    case "STATS": {
      // Normalize the health and stamina values to a percentage value with 0-100
      const health = (data.health / data.max_health) * 100;
      const stamina = (data.stamina / data.max_stamina) * 100;
      updateStats(health, stamina);
      // Update the player's stats so the health and stamina bars are accurate
      players.forEach((player) => {
        if (player.id === data.id) {
          player.stats = data;
        }
      });
      break;
    }
    case "CLIENTCONFIG": {
      const data = JSON.parse(packet.decode(event.data))["data"][0];
      fpsSlider.value = data.fps;
      document.getElementById(
        "limit-fps-label"
      )!.innerText = `FPS: (${fpsSlider.value})`;
      musicSlider.value = data.music_volume;
      document.getElementById(
        "music-volume-label"
      )!.innerText = `Music: (${musicSlider.value})`;
      effectsSlider.value = data.effects_volume;
      document.getElementById(
        "effects-volume-label"
      )!.innerText = `Effects: (${effectsSlider.value})`;
      mutedCheckbox.checked = data.muted;
      document.getElementById(
        "muted-checkbox"
      )!.innerText = `Muted: ${mutedCheckbox.checked}`;
      break;
    }
    case "SELECTPLAYER": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      if (!data || !data.id || !data.username) {
        players.forEach((player) => {
          player.targeted = false;
        });
        targetStats.style.display = "none";
        updateTargetStats(0, 0);
        break;
      } else {
        players.forEach((player) => {
          if (player.id === data.id) {
            player.targeted = true;
            targetStats.style.display = "block";
            updateTargetStats(player.stats.health, player.stats.stamina);
          } else {
            player.targeted = false;
          }
        });
      }
      break;
    }
    case "STEALTH": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      const currentPlayer = players.find(
        (player) => player.id === sessionStorage.getItem("connectionId")
      );

      players.forEach((player) => {
        if (player.id === data.id) {
          player.isStealth = data.isStealth;
        }
        // Untarget if the player is stealthed and targeted
        if (player.isStealth && player.targeted) {
          player.targeted = false;
          targetStats.style.display = "none";
          updateTargetStats(0, 0);
        }

        const dot = document.querySelector(`[data-id="${player.id}"]`) as HTMLElement;
        if (!dot) return;
        if (player.isStealth) {
          if (currentPlayer?.isAdmin) {
            dot.style.opacity = "1";
          } else {
            dot.style.opacity = "0";
          }
        } else {
          dot.style.opacity = "1";
        }
      });
      break;
    }
    case "UPDATESTATS": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      const target = players.find((player) => player.id === data.target);
      if (!target) return;
      target.stats = data.stats;
      if (target.id === sessionStorage.getItem("connectionId")) {
        updateStats(target.stats.health, target.stats.stamina);
      } else {
        updateTargetStats(target.stats.health, target.stats.stamina);
      }
      break;
    }
    case "REVIVE": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      const target = players.find((player) => player.id === data.target);
      if (!target) return;
      target.stats = data.stats;
      if (target.id === sessionStorage.getItem("connectionId")) {
        updateStats(target.stats.health, target.stats.stamina);
      } else {
        target.targeted = false;
        updateTargetStats(0, 0);
      }

      // untarget all players
      targetStats.style.display = "none";
      players.forEach((player) => {
        player.targeted = false;
      });
      break;
    }
    case "AUDIO": {
      const name = JSON.parse(packet.decode(event.data))["name"];
      const data = JSON.parse(packet.decode(event.data))["data"];
      const pitch = JSON.parse(packet.decode(event.data))["pitch"] || 1;
      const timestamp = JSON.parse(packet.decode(event.data))["timestamp"];
      playAudio(name, data.data.data, pitch, timestamp);
      break;
    }
    case "MUSIC": {
      const name = JSON.parse(packet.decode(event.data))["name"];
      const data = JSON.parse(packet.decode(event.data))["data"];
      const timestamp = JSON.parse(packet.decode(event.data))["timestamp"];
      playMusic(name, data.data.data, timestamp);
      break;
    }
    case "INSPECTPLAYER": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      // Add the player ID as an attribute to the target stats container
      statUI.setAttribute("data-id", data.id);
      healthLabel!.innerText = `Health: (${data.stats.health})`;
      manaLabel!.innerText = `Mana: (${data.stats.stamina})`;
      statUI.style.transition = "1s";
      statUI.style.left = "10";
      break;
    }
    case "NOTIFY": {
      const data = JSON.parse(packet.decode(event.data))["data"];
      showNotification(data.message, true, false);
      break;
    }
    default:
      break;
  }
}

function playMusic(name: string, data: Uint8Array, timestamp: number): void {
// Check if the audio is already cached, if not, inflate the data
    // @ts-expect-error - pako is not defined because it is loaded in the index.html
    const cachedAudio = timestamp < performance.now() - 3.6e+6 ? pako.inflate(new Uint8Array(data),{ to: 'string' }) : audioCache.get(name)|| pako.inflate(new Uint8Array(data), { to: 'string' });
    const music = new Audio(`data:audio/wav;base64,${cachedAudio}`);
    if (!music) {
      console.error("Failed to create audio element");
      return;
    }
    const musicVolume = Number(musicSlider.value);
    music.volume = mutedCheckbox.checked || musicVolume === 0 ? 0 : musicVolume / 100;
    music.loop = true;
    try {
      music.play();
      // Cache the audio
      audioCache.set(name, cachedAudio);
      startMusicInterval(music);
    } catch (e) {
      console.error(e);
    }
}

function startMusicInterval(music: any) {
  setInterval(() => {
    const musicVolume = Number(musicSlider.value);
    music.volume = mutedCheckbox.checked || musicVolume === 0 ? 0 : musicVolume / 100;
  }, 100);
}

function playAudio(name: string, data: Uint8Array, pitch: number, timestamp: number): void {
  // Get mute status
  if (mutedCheckbox.checked) return;
  // Get effects volume
  const volume = effectsSlider.value === "0" ? 0 : Number(effectsSlider.value) / 100;
  // Check if the audio is already cached, if not, inflate the data
  // @ts-expect-error - pako is not defined because it is loaded in the index.html
  const cachedAudio = timestamp < performance.now() - 3.6e+6 ? pako.inflate(new Uint8Array(data),{ to: 'string' }) : audioCache.get(name)|| pako.inflate(new Uint8Array(data), { to: 'string' });
  const audio = new Audio(`data:audio/wav;base64,${cachedAudio}`);
  if (!audio) {
    console.error("Failed to create audio element");
    return;
  }
  audio.playbackRate = pitch;
  audio.volume = volume;
  // Auto play
  audio.autoplay = true;

  try {
    audio.play();
    // Cache the audio
    audioCache.set(name, cachedAudio);
  } catch (e) {
    console.error(e);
  }  
}

function getCookie(cname: string) {
  const name = cname + "=";
  const decodedCookie = decodeURIComponent(document.cookie);
  const ca = decodedCookie.split(";");
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == " ") {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

let isKeyPressed = false;
let isMoving = false;
const pressedKeys = new Set();
const movementKeys = new Set(["KeyW", "KeyA", "KeyS", "KeyD"]);

window.addEventListener("keydown", async (e) => {
  if (!loaded) return;
  if (movementKeys.has(e.code) && chatInput !== document.activeElement) {
    if (pauseMenu.style.display == "block") return;
    pressedKeys.add(e.code);
    if (!isKeyPressed) {
      isKeyPressed = true;
      if (!isMoving) {
        handleKeyPress();
      }
    }
  }

  // Open pause menu
  if (e.code === "Escape") {
    if (!loaded) return;
    chatInput.blur();
    // If any menu is open, close it
    if (
      document.getElementById("pause-menu-container")?.style.display != "block"
    ) {
      pauseMenu.style.display = "block";
    } else {
      pauseMenu.style.display = "none";
    }

    for (const element of menuElements) {
      if (document.getElementById(element)?.style.display == "block") {
        const menuElement = document.getElementById(element);
        if (menuElement) {
          menuElement.style.display = "none";
        }
      }
    }
  }

  // Open inventory UI
  if (e.code === "KeyB") {
    if (!loaded) return;
    if (chatInput === document.activeElement) return;
    if (pauseMenu.style.display == "block") return;
    if (toggleInventory) {
      inventoryUI.style.transition = "1s";
      inventoryUI.style.right = "-350";
      toggleInventory = false;
    } else {
      inventoryUI.style.transition = "1s";
      inventoryUI.style.right = "10";
      toggleInventory = true;
    }
  }

  // Open Stats UI
  if (e.code === "KeyC") {
    if(!loaded) return;
    if (chatInput === document.activeElement) return;
    if (pauseMenu.style.display == "block") return;
    // If the menu is open and the current players id is the data-id attribute of the target stats container, close the menu
    if (statUI.style.left === "10px" && statUI.getAttribute("data-id") === sessionStorage.getItem("connectionId")) {
      statUI.style.transition = "1s";
      statUI.style.left = "-570";
    } else {
      socket.send(
        packet.encode(
          JSON.stringify({
            type: "INSPECTPLAYER",
            data: null,
          })
        )
      );
    }
  }

  // Open Full Map
  if (e.code === "KeyM") {
    if(!loaded) return;
    if (chatInput === document.activeElement) return;
    if (pauseMenu.style.display == "block") return;
    if (fullmap.style.display === "block") {
      fullmap.style.display = "none";
    } else {
      fullmap.style.display = "block";
      updatePlayerDots();
    }
  }

  if (e.code === "Tab") {
    e.preventDefault();
    if (!loaded) return;
    if (chatInput === document.activeElement) return;
    if (pauseMenu.style.display == "block") return;
    socket.send(
      packet.encode(
        JSON.stringify({
          type: "TARGETCLOSEST",
          data: null,
        })
      )
    );
  }

  if (e.code === "KeyX") {
    if (!loaded) return;
    if (chatInput === document.activeElement) return;
    if (pauseMenu.style.display == "block") return;
    socket.send(packet.encode(JSON.stringify({ type: "STEALTH", data: null })));
  }

  if (e.code === "KeyZ") {
    if (!loaded) return;
    if (chatInput === document.activeElement) return;
    if (pauseMenu.style.display == "block") return;
    socket.send(packet.encode(JSON.stringify({ type: "NOCLIP", data: null })));
  }

  if (e.code === "Enter" && chatInput !== document.activeElement) {
    if (pauseMenu.style.display == "block") return;
    chatInput.focus();
  } else if (e.code === "Enter" && chatInput == document.activeElement) {
    if (pauseMenu.style.display == "block") return;
    if (!chatInput?.value || chatInput?.value?.trim() === "") {
      chatInput.value = "";
      chatInput.blur();
      return;
    }

    // Check if we are sending a command
    if (chatInput.value.trim().startsWith("/")) {
      const command = chatInput.value.trim().substring(1);
      // Match either quoted strings or non-space sequences
      const commandParts = command.match(/[^\s"]+|"([^"]*)"/g) || [];
      // Remove quotes and get command name and args
      const commandName = commandParts[0];
      const commandArgs = commandParts.slice(1).map(arg => 
        arg.startsWith('"') ? arg.slice(1, -1) : arg
      );

      socket.send(
        packet.encode(
          JSON.stringify({
            type: "COMMAND",
            data: {
              command: commandName,
              args: commandArgs,
            },
          })
        )
      );
      chatInput.value = "";
      chatInput.blur();
      return;
    } 
    if (window?.crypto?.subtle) {
      const publicKey = sessionStorage.getItem("publicKey");
      if (!publicKey) return;
      const encryptedMessage = await encryptRsa(publicKey, chatInput.value.trim().toString() || " ");
      socket.send(
        packet.encode(
          JSON.stringify({
            type: "CHAT",
            data: {
              message: encryptedMessage,
              mode: "decrypt"
            }
          })
        )
      );
    } else {
      // Fallback to non-encrypted chat if Web Crypto API is not available
      socket.send(
        packet.encode(
          JSON.stringify({
            type: "CHAT",
            data: {
              message: chatInput.value.trim().toString() || " ",
              mode: null
            }
          })
        )
      );
    }

    const previousMessage = chatInput.value.trim();
    if (previousMessage === "") return;

    setTimeout(async () => {
      // Check if the chat is still the same value
      for (const player of players) {
      if (player.id === sessionStorage.getItem("connectionId")) {
        if (player.chat === previousMessage) {
        socket.send(
          packet.encode(
          JSON.stringify({
            type: "CHAT",
            data: null,
          })
          )
        );
        }
      }
      }
    }, 7000 + chatInput.value.length * 35);
    chatInput.value = "";
    chatInput.blur();
  }

  if (e.code === "Space") {
    if (!loaded) return;
    // Check if paused
    if (pauseMenu.style.display == "block") return;
    const target = players.find((player) => player.targeted);
    if (!target) return;
    socket.send(
      packet.encode(
        JSON.stringify({
          type: "ATTACK",
          data: target,
        })
      )
    );
  }

  const blacklistedKeys = ['AltLeft', 'AltRight', 'ControlLeft', 'ControlRight', 'ShiftLeft', 'ShiftRight'];
  if (blacklistedKeys.includes(e.code)) {
    e.preventDefault();
  }
});

// Listen for keyup events to stop movement
window.addEventListener("keyup", (e) => {
  if (chatInput === document.activeElement) return;
  if (movementKeys.has(e.code)) {
    pressedKeys.delete(e.code);
    if (pressedKeys.size === 0) {
      isKeyPressed = false;
    }
  }
});

function handleKeyPress() {
  if (!loaded || controllerConnected) return;
  if (pauseMenu.style.display == "block") return;
  if (isMoving) return;

  isMoving = true;
  let lastDirection = ""; // Track last sent direction

  function runMovement() {
    if (!isKeyPressed) {
      // Send abort packet when movement stops
      if (lastDirection !== "") {
        socket.send(
          packet.encode(
            JSON.stringify({
              type: "MOVEXY",
              data: "ABORT",
            })
          )
        );
      }
      isMoving = false;
      lastDirection = "";
      return;
    }

    if (pauseMenu.style.display == "block") return;

    let currentDirection = "";

    // Calculate current direction based on pressed keys
    if (pressedKeys.size > 1) {
      if (pressedKeys.has("KeyW") && pressedKeys.has("KeyA")) {
        currentDirection = "UPLEFT";
      } else if (pressedKeys.has("KeyW") && pressedKeys.has("KeyD")) {
        currentDirection = "UPRIGHT";
      } else if (pressedKeys.has("KeyS") && pressedKeys.has("KeyA")) {
        currentDirection = "DOWNLEFT";
      } else if (pressedKeys.has("KeyS") && pressedKeys.has("KeyD")) {
        currentDirection = "DOWNRIGHT";
      }
    } else {
      if (pressedKeys.has("KeyW")) {
        currentDirection = "UP";
      } else if (pressedKeys.has("KeyS")) {
        currentDirection = "DOWN";
      } else if (pressedKeys.has("KeyA")) {
        currentDirection = "LEFT";
      } else if (pressedKeys.has("KeyD")) {
        currentDirection = "RIGHT";
      }
    }

    // Only send if direction changed
    if (currentDirection !== "" && currentDirection !== lastDirection) {
      socket.send(
        packet.encode(
          JSON.stringify({
            type: "MOVEXY",
            data: currentDirection,
          })
        )
      );
      lastDirection = currentDirection;
    }

    setTimeout(runMovement, 0);
  }

  runMovement();
}

async function isLoaded() {
  // Check every second if the map is loaded
  await new Promise<void>((resolve) => {
    const interval = setInterval(() => {
      if (loaded) {
        clearInterval(interval);

        resolve();
      }
    }, 10);
  });
}

function createNPC(data: any) {
  const npc: {
    id: string;
    position: { x: number; y: number };
    dialog: string;
    particles: Particle[];
    quest: number | null;
    show: (context: CanvasRenderingContext2D) => void;
    updateParticle: (particle: Particle, npc: any, context: CanvasRenderingContext2D) => void;
  } = {
    id: data.id,
    dialog: data.dialog || "",
    position: {
      x: npcCanvas.width / 2 + data.location.x,
      y: npcCanvas.height / 2 + data.location.y,
    },
    particles: data.particles || [],
    quest: data.quest || null,
    show: function (this: typeof npc, context: CanvasRenderingContext2D) {
      if (!npcImage || !context) return;
      // Get current players admin status
      const currentPlayer = players.find(
        (player) => player.id === sessionStorage.getItem("connectionId")
      );
      if (data?.hidden && !currentPlayer?.isAdmin) return;
      context.drawImage(npcImage, this.position.x, this.position.y, npcImage.width, npcImage.height);

      context.fillStyle = "black";
      context.fillStyle = "white";
      context.font = "14px 'Brush Script MT', cursive";
      context.textAlign = "center";
      if (this.dialog) {
        if (this.dialog.trim() !== "") {
          const lines = getLines(context, this.dialog, 500).reverse();
          let startingPosition = this.position.y;

          for (let i = 0; i < lines.length; i++) {
            startingPosition -= 15;
            context.fillText(lines[i], this.position.x + 16, startingPosition);
          }
        }
      }
    },
    updateParticle: async (particle: Particle, npc: any, context: CanvasRenderingContext2D) => {
      // Initialize particle arrays and timing for each type if they don't exist
      if (!npc.particleArrays) {
        npc.particleArrays = {};
        npc.lastEmitTime = {};
      }
      
      const currentTime = performance.now();
      const emitInterval = (particle.interval || 1) * 16.67; // Convert to milliseconds (60fps = 16.67ms)
      
      // Initialize or get the last emit time for this particle type
      if (!npc.lastEmitTime[particle.name || '']) {
        npc.lastEmitTime[particle.name || ''] = currentTime;
      }
      
      // Initialize particle array if it doesn't exist
      if (!npc.particleArrays[particle.name || '']) {
        npc.particleArrays[particle.name || ''] = [];
      }

      // Check if it's time to emit a new particle
      if (currentTime - npc.lastEmitTime[particle.name || ''] >= emitInterval) {
        const randomLifetimeExtension = Math.random() * (particle.staggertime || 0);
        const baseLifetime = particle.lifetime || 1000;
        const windDirection = typeof particle.weather === 'object' ? particle.weather.wind_direction : null;
        const windSpeed = typeof particle.weather === 'object' ? particle.weather.wind_speed || 0 : 0;

        // Default wind bias to 0
        const windBias = {
          x: 0,
          y: 0
        }

        if (windDirection !== null && (windDirection === 'left' || windDirection === 'right')) {
          // Apply wind direction bias to initial position
          const windDirectionRad = (windDirection === 'left' ? 180 : 
                                  windDirection === 'right' ? 0 : 180) * Math.PI / 180;
          windBias.x = Math.cos(windDirectionRad) * windSpeed * 0.5;
          windBias.y = Math.sin(windDirectionRad) * windSpeed * 0.5;
        }

        const newParticle: Particle = {
          ...particle,
          localposition: { 
            x: Number(particle.localposition?.x || 0) + (Math.random() < 0.5 ? -1 : 1) * Math.random() * Number(particle.spread.x),
            y: Number(particle.localposition?.y || 0) + (Math.random() < 0.5 ? -1 : 1) * Math.random() * Number(particle.spread.y)
          },
          velocity: { 
            x: Number(particle.velocity.x || 0) + windBias.x,
            y: Number(particle.velocity.y || 0) + windBias.y
          },
          lifetime: baseLifetime + randomLifetimeExtension,
          currentLife: baseLifetime + randomLifetimeExtension,
          opacity: particle.opacity || 1,
          visible: true,
          size: particle.size || 5,
          color: particle.color || 'white',
          gravity: { ...particle.gravity },
          weather: typeof particle.weather === 'object' ? { ...particle.weather } : 'none'
        };

        // Remove oldest particle if we exceed the maximum amount
        if (npc.particleArrays[particle.name || ''].length >= particle.amount) {
          npc.particleArrays[particle.name || ''].shift();
        }
        
        npc.particleArrays[particle.name || ''].push(newParticle);
        npc.lastEmitTime[particle.name || ''] = currentTime;
      }

      // Update and render existing particles for this type
      const particles = npc.particleArrays[particle.name || ''];
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        
        // Decrease lifetime
        p.currentLife--;

        // Remove dead particles
        if (p.currentLife <= 0) {
          particles.splice(i, 1);
          continue;
        }

        if (!p.localposition) {
          p.localposition = { x: 0, y: 0 };
        }

        // Apply gravity and wind effects
        if (p.velocity && p.gravity) {
          const windDirection = typeof p.weather === 'object' ? p.weather.wind_direction : null;
          const windSpeed = typeof p.weather === 'object' ? p.weather.wind_speed || 0 : 0;
          const windForce = {
            x: 0,
            y: 0
          };

          if (windDirection !== 'none' && (windDirection === 'left' || windDirection === 'right')) {
            const windDirectionRad = (windDirection === 'left' ? 180 : 0) * Math.PI / 180;
            windForce.x = Math.cos(windDirectionRad) * windSpeed * 0.01;
            windForce.y = Math.sin(windDirectionRad) * windSpeed * 0.01;
          }

          // Update velocity with gravity and wind
          p.velocity.x += p.gravity.x * 0.01 + windForce.x;
          p.velocity.y += p.gravity.y * 0.01 + windForce.y;
          
          // Cap velocity considering wind influence
          const maxVelocity = {
            x: particle.velocity.x + (windSpeed * 0.2),
            y: particle.velocity.y + (windSpeed * 0.2)
          };
          
          p.velocity.x = Math.min(Math.max(p.velocity.x, -maxVelocity.x), maxVelocity.x);
          p.velocity.y = Math.min(Math.max(p.velocity.y, -maxVelocity.y), maxVelocity.y);
          
          // Update position
          p.localposition.x += p.velocity.x * 0.01;
          p.localposition.y += p.velocity.y * 0.01;
        }

        // Calculate render position
        const centerX = npc.position.x + 16 - (p.size / 2);
        const centerY = npc.position.y + 24 - (p.size / 2);
        const renderX = centerX + p.localposition.x;
        const renderY = centerY + p.localposition.y;

        // Calculate fade in/out alpha
        const fadeInDuration = p.lifetime * 0.4;
        const fadeOutDuration = p.lifetime * 0.4;
        let alpha;

        if (p.lifetime - p.currentLife < fadeInDuration) {
          // Fade in
          alpha = ((p.lifetime - p.currentLife) / fadeInDuration) * p.opacity;
        } else if (p.currentLife < fadeOutDuration) {
          // Fade out
          alpha = (p.currentLife / fadeOutDuration) * p.opacity;
        } else {
          // Fully visible
          alpha = p.opacity;
        }
        
        context.globalAlpha = alpha;

        // Draw particle as a circle
        context.beginPath();
        context.arc(renderX + p.size/2, renderY + p.size/2, p.size/2, 0, Math.PI * 2);
        context.fillStyle = p.color || "white";
        context.fill();
      }

      // Reset global alpha for other rendering
      context.globalAlpha = 1;
    }
  };

  npcs.push(npc);

  // Make a copy of the npc object to prevent the original object from being modified
  const _npc = Object.assign({}, npc) as any;
  // Delete unnecessary properties from the copied npc object
  delete _npc.show;
  
  Object.defineProperties(_npc, {
    id: { writable: false, configurable: false },
    position: { writable: false, configurable: false },
    dialog: { writable: false, configurable: false },
    quest: { writable: false, configurable: false },
  });

  // Execute the npc script in a sandboxed environment where "this" refers to the npc object
  try {
    (async function () {
      await isLoaded();
      new Function(
        "with(this) { " + decodeURIComponent(data.script) + " }"
      ).call(_npc);
    }).call(_npc);
  } catch (e) {
    console.error(e);
  }
}

function createPlayer(data: any) {
  // @ts-expect-error - pako is not defined because it is loaded in the index.html
  const inflatedData = pako.inflate(new Uint8Array(data.sprite.data));
  const base64Data = btoa(
    Array.from(inflatedData as Uint8Array).map(byte => String.fromCharCode(byte)).join('')
  );
  const sprite_idle = new Image();
  sprite_idle.src = `data:image/png;base64,${base64Data}`;

  const player = {
    id: data.id,
    position: {
      x: playerCanvas.width / 2 + data.location.x,
      y: playerCanvas.height / 2 + data.location.y,
    },
    chat: "",
    isStealth: data.isStealth,
    isAdmin: data.isAdmin,
    targeted: false,
    sprite: sprite_idle,
    stats: data.stats,
    show: function (context: CanvasRenderingContext2D) {
      context.globalAlpha = 1;
      context.font = "14px 'Brush Script MT', cursive";
      
      // Opacity for stealth mode
      if (this.isStealth) {
        context.fillStyle = "rgba(97, 168, 255, 1)";
      } else {
        context.fillStyle = "white";
      }

      // Draw the player's username
      context.textAlign = "center";

      // Current player
      if (data.id === sessionStorage.getItem("connectionId") && !this.isStealth) {
        context.fillStyle = "#ffe561";
      } else {
        if (this.targeted) {
          context.fillStyle = "#E01F1F";
        } else {
          if (this.isStealth) {
            context.fillStyle = "rgba(97, 168, 255, 1)";
          } else {
            context.fillStyle = "#ffffff";
          }
        }
      }

      context.shadowColor = "black";
      context.shadowBlur = 2;
      context.shadowOffsetX = 0;
      context.strokeStyle = "black";
      
      // Uppercase the first letter of the username
      data.username =
        data.username.charAt(0).toUpperCase() + data.username.slice(1);
      // Display (Admin) tag if the player is an admin
      if (data.isAdmin) {
        context.strokeText(
          data.username + " (Admin)",
          this.position.x + 16,
          this.position.y + 65
        );
        context.fillText(
          data.username + " (Admin)",
          this.position.x + 16,
          this.position.y + 65
        );
      } else {
        context.strokeText(
          data.username,
          this.position.x + 16,
          this.position.y + 65
        );
        context.fillText(
          data.username,
          this.position.x + 16,
          this.position.y + 65
        );
      }

      // Draw the player's chat message
      context.fillStyle = "black";
      context.fillStyle = "white";
      context.textAlign = "center";
      context.shadowBlur = 1;
      context.shadowColor = "black";
      context.shadowOffsetX = 1;
      context.shadowOffsetY = 1;
      
      if (this.chat) {
        if (this.chat.trim() !== "") {
          const lines = getLines(context, this.chat, 500).reverse();
          let startingPosition = this.position.y;

          for (let i = 0; i < lines.length; i++) {
            startingPosition -= 20;
            // Draw background
            const textWidth = context.measureText(lines[i]).width;
            context.fillStyle = "rgba(0, 0, 0, 0.2)";
            context.fillRect(
              this.position.x + 16 - textWidth/2 - 5, // Center background
              startingPosition - 17, // Slightly above text
              textWidth + 10, // Add padding
              20 // Height of background
            );
            // Draw text
            context.fillStyle = "white";
            context.fillText(lines[i], this.position.x + 16, startingPosition);
          }
        }
      }

      // Draw the player's health bar below the player's name with a width of 100px, centered below the player name
      if (!this.isStealth) {
        context.fillStyle = "rgba(0, 0, 0, 0.8)";
        context.fillRect(this.position.x - 34, this.position.y + 71, 100, 3);

        // Update the shadowblur to 2
        context.shadowBlur = 2;
        
        // Set health bar color based on health percentage
        const healthPercent = this.stats.health / this.stats.max_health;
        if (healthPercent < 0.3) {
          context.fillStyle = "#C81D1D"; // red
        } else if (healthPercent < 0.5) {
          context.fillStyle = "#C87C1D"; // orange
        } else if (healthPercent < 0.8) {
          context.fillStyle = "#C8C520"; // yellow
        } else {
          context.fillStyle = "#519D41"; // green
        }
        
        context.fillRect(
          this.position.x - 34,
          this.position.y + 71,
          healthPercent * 100,
          3
        );

        // Draw the player's stamina bar below the player's health bar with a width of 75px, centered below the player's health bar
        context.fillStyle = "rgba(0, 0, 0, 0.8)";
        context.fillRect(this.position.x - 34, this.position.y + 76, 100, 3);
        context.fillStyle = "#469CD9";
        context.fillRect(
          this.position.x - 34,
          this.position.y + 76,
          (this.stats.stamina / this.stats.max_stamina) * 100,
          3
        );
      }

      // Reset shadow settings
      context.shadowColor = "transparent";
      context.shadowBlur = 0;

      if (this.isStealth) {
        context.globalAlpha = 0.5;
      }

      if (this.sprite) {
        context.drawImage(this.sprite, this.position.x, this.position.y, 32, 48);
      } else {
        context.fillRect(this.position.x, this.position.y, 32, 48);
      }
    },
  };

  // Current player
  if (data.id === sessionStorage.getItem("connectionId")) {
    // Initialize camera position immediately for the current player
    cameraX = player.position.x - window.innerWidth / 2 + 8;
    cameraY = player.position.y - window.innerHeight / 2 + 48;
    window.scrollTo(cameraX, cameraY);
  }

  players.push(player);

  // Update player dots on the full map if it is open
  if (fullmap.style.display === "block") {
    updatePlayerDots();
  }
}

function getLines(ctx: any, text: string, maxWidth: number) {
  const words = text.split(" ");
  const lines = [];
  let currentLine = words[0];

  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    const width = ctx.measureText(currentLine + " " + word).width;
    if (width < maxWidth) {
      currentLine += " " + word;
    } else {
      lines.push(currentLine);
      currentLine = word;
    }
  }
  lines.push(currentLine);
  return lines;
}

// Snap to player's position on resize
window.addEventListener("resize", () => {
  const clientSocketId = sessionStorage.getItem("connectionId");
  const currentPlayer = players.find((player) => player.id === clientSocketId);
  if (currentPlayer) {
    cameraX = currentPlayer.position.x - window.innerWidth / 2 + 8;
    cameraY = currentPlayer.position.y - window.innerHeight / 2 + 48;
    window.scrollTo(cameraX, cameraY);
  }
});

// Prevent unfocusing the window
window.addEventListener("blur", () => {
  isKeyPressed = false;
  // Clear the pressedKeys set
  pressedKeys.clear();
});

function updateStats(health: number, stamina: number) {
  healthBar.removeAttribute("class");
  healthBar.classList.add("ui");
  healthBar.style.width = `${health}%`;
  staminaBar.style.width = `${stamina}%`;
  if (health >= 80) {
    healthBar.classList.add("green");
    return;
  }
  if (health >= 50 && health < 80) {
    healthBar.classList.add("yellow");
    return;
  }
  if (health >= 30 && health < 50) {
    healthBar.classList.add("orange");
    return;
  }
  if (health < 30) {
    healthBar.classList.add("red");
    return;
  }
}

function updateTargetStats(health: number, stamina: number) {
  targetHealthBar.removeAttribute("class");
  targetHealthBar.classList.add("ui");
  targetHealthBar.style.width = `${health}%`;
  targetStaminaBar.style.width = `${stamina}%`;
  if (health >= 80) {
    targetHealthBar.classList.add("green");
    return;
  }
  if (health >= 50 && health < 80) {
    targetHealthBar.classList.add("yellow");
    return;
  }
  if (health >= 30 && health < 50) {
    targetHealthBar.classList.add("orange");
    return;
  }
  if (health < 30) {
    targetHealthBar.classList.add("red");
    return;
  }
}

function updatePlayerDots() {
  const currentPlayer = players.find(
    (player) => player.id === sessionStorage.getItem("connectionId")
  );
  // Add a new dot for each player
  players.forEach((player) => {
    if (player.id === sessionStorage.getItem("connectionId")) {
      const dot = document.getElementsByClassName("self")[0] as HTMLElement;
      if (dot) {
        dot.style.left = `${player.position.x * mapScale}px`;
        dot.style.top = `${player.position.y * mapScale}px`;
      } else {
        const newDot = document.createElement("div");
        newDot.classList.add("dot");
        newDot.classList.add("self");
        newDot.style.left = `${player.position.x * mapScale}px`;
        newDot.style.top = `${player.position.y * mapScale}px`;
        fullmap.appendChild(newDot);
      }
    } else {
      // Get by data-id attribute
      const dot = document.querySelector(`[data-id="${player.id}"]`) as HTMLElement;
      if (dot) {
        dot.style.left = `${player.position.x * mapScale}px`;
        dot.style.top = `${player.position.y * mapScale}px`;
        if (player.isStealth) {
          if (currentPlayer?.isAdmin) {
            dot.style.opacity = "1";
          } else {
            dot.style.opacity = "0";
          }
        } else {
          dot.style.opacity = "1";
        }
      } else {
        const newDot = document.createElement("div");
        newDot.classList.add("dot");
        newDot.classList.add("other");
        newDot.setAttribute("data-id", player.id);
        newDot.style.left = `${player.position.x * mapScale}px`;
        newDot.style.top = `${player.position.y * mapScale}px`;
        if (player.isStealth) {
          if (currentPlayer?.isAdmin) {
            newDot.style.opacity = "1";
          } else {
            newDot.style.opacity = "0";
          }
        } else {
          newDot.style.opacity = "1";
        }
        fullmap.appendChild(newDot);
      }
    }
  });
}

async function updateFullMap() {
  if (!loaded) return;

  // Generate the data URL for the full map
  const dataUrl = canvas.toDataURL("image/png");

  const image = fullmap.querySelector("img");

  if (image) {
    image.src = dataUrl;
  } else {
    const newImage = new Image();
    newImage.src = dataUrl;
    fullmap.appendChild(newImage);
  }

  fullmap.style.width = canvas.width * mapScale + "px";
  fullmap.style.height = canvas.height * mapScale + "px";
}

document
  .getElementById("pause-menu-action-back")
  ?.addEventListener("click", () => {
    pauseMenu.style.display = "none";
  });

document
  .getElementById("pause-menu-action-options")
  ?.addEventListener("click", () => {
    // If any other menu is open, close all other menus
    pauseMenu.style.display = "none";
    optionsMenu.style.display = "block";
  });

document
  .getElementById("pause-menu-action-exit")
  ?.addEventListener("click", () => {
    socket.send(
      packet.encode(
        JSON.stringify({
          type: "LOGOUT",
          data: null,
        })
      )
    );
    window.location.href = "/";
  });

fpsSlider.addEventListener("input", () => {
  document.getElementById(
    "limit-fps-label"
  )!.innerText = `FPS: (${fpsSlider.value})`;
});

musicSlider.addEventListener("input", () => {
  document.getElementById(
    "music-volume-label"
  )!.innerText = `Music: (${musicSlider.value})`;
});

effectsSlider.addEventListener("input", () => {
  document.getElementById(
    "effects-volume-label"
  )!.innerText = `Effects: (${effectsSlider.value})`;
});

fpsSlider.addEventListener("change", () => {
  socket.send(
    packet.encode(
      JSON.stringify({
        type: "CLIENTCONFIG",
        data: {
          fps: parseInt(fpsSlider.value),
          music_volume: parseInt(musicSlider.value),
          effects_volume: parseInt(effectsSlider.value),
          muted: mutedCheckbox.checked,
        } as ConfigData,
      })
    )
  );
});

musicSlider.addEventListener("change", () => {
  socket.send(
    packet.encode(
      JSON.stringify({
        type: "CLIENTCONFIG",
        data: {
          fps: parseInt(fpsSlider.value),
          music_volume: parseInt(musicSlider.value),
          effects_volume: parseInt(effectsSlider.value),
          muted: mutedCheckbox.checked,
        } as ConfigData,
      })
    )
  );
});

effectsSlider.addEventListener("change", () => {
  socket.send(
    packet.encode(
      JSON.stringify({
        type: "CLIENTCONFIG",
        data: {
          fps: parseInt(fpsSlider.value),
          music_volume: parseInt(musicSlider.value),
          effects_volume: parseInt(effectsSlider.value),
          muted: mutedCheckbox.checked,
        } as ConfigData,
      })
    )
  );
});

mutedCheckbox.addEventListener("change", () => {
  socket.send(
    packet.encode(
      JSON.stringify({
        type: "CLIENTCONFIG",
        data: {
          fps: parseInt(fpsSlider.value),
          music_volume: parseInt(musicSlider.value),
          effects_volume: parseInt(effectsSlider.value),
          muted: mutedCheckbox.checked,
        } as ConfigData,
      })
    )
  );
});

// Capture click and get coordinates from canvas
document.addEventListener("contextmenu", (event) => {
  if (!loaded) return;
  if ((event.target as HTMLElement)?.classList.contains("ui")) return;
  // Check where we clicked on the canvas
  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;

  const moveX = Math.floor(x - playerCanvas.width / 2 - 16);
  const moveY = Math.floor(y - playerCanvas.height / 2 - 24);
  socket.send(
    packet.encode(
      JSON.stringify({
        type: "TELEPORTXY",
        data: { x: moveX, y: moveY },
      })
    )
  );
});

document.addEventListener("click", (event) => {
  // Check if we clicked on a player
  if (!loaded) return;
  if ((event.target as HTMLElement)?.classList.contains("ui")) return;
  if ((event.target as HTMLElement)?.id != "players") return;

  const rect = canvas.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;

  const moveX = x - playerCanvas.width / 2 - 16;
  const moveY = y - playerCanvas.height / 2 - 24;

  socket.send(
    packet.encode(
      JSON.stringify({
        type: "SELECTPLAYER",
        data: { x: moveX, y: moveY },
      })
    )
  );
});

async function encryptRsa(publicKey: string, data: string) {
  const cleanedKey = cleanBase64Key(publicKey);
  const importedKey = await window.crypto.subtle.importKey(
    "spki",
    new Uint8Array(atob(cleanedKey).split('').map(c => c.charCodeAt(0))),
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["encrypt"]
  );

  const encoded = new TextEncoder().encode(data);
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    importedKey,
    encoded
  );

  return new Uint8Array(encrypted);
}

function cleanBase64Key(base64Key: string): string {
  return base64Key.replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
}

/* Notifications */
const notificationContainer = document.getElementById("game-notification-container");
const notificationMessage = document.getElementById("game-notification-message");
let clearNotificationTimeout: any = null;

function showNotification(message: string, autoClose: boolean = true, reconnect: boolean = false) {

  if (!notificationContainer || !notificationMessage) return;
  
  notificationMessage.innerText = message;
  notificationContainer.style.display = "flex";
  
  const baseTimeout = 5000; // Base timeout of 5 seconds
  const timePerChar = 100; // Additional time per character in milliseconds
  const timeout = baseTimeout + (message.length * timePerChar);

  if (autoClose) {
    // Clear any existing timeout
    if (clearNotificationTimeout) {
      clearTimeout(clearNotificationTimeout);
    }
    clearNotificationTimeout = setTimeout(() => {
      notificationContainer.style.display = "none";
      // If reconnect is true, redirect after hiding notification
      if (reconnect) {
        window.location.href = "/";
      }
    }, timeout);
  } else if (reconnect) {
    // If not auto-closing but need to reconnect
    setTimeout(() => {
      window.location.href = "/";
    }, timeout);
  }
}