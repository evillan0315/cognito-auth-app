/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { UseGuards } from '@nestjs/common';
import {
  WebSocketGateway,
  WebSocketServer,
  SubscribeMessage,
  MessageBody,
  ConnectedSocket,
  OnGatewayConnection,
  OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { spawn } from 'child_process';
import * as os from 'os';
import * as process from 'process';
import { resolve } from 'path';
import { existsSync, statSync } from 'fs';
import { exec } from 'child_process';
import { CognitoWsGuard } from '../aws/cognito/cognito.ws.guard';
import * as cookie from 'cookie';
import { DynamodbService } from '../dynamodb/dynamodb.service';

@WebSocketGateway({
  cors: {
    origin: ['http://localhost:5173'],
    credentials: true,
  },
})
@UseGuards(CognitoWsGuard)
export class TerminalGateway
  implements OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer()
  server: Server;
  private clientDirectories: Map<string, string> = new Map();
  constructor(private readonly dynamodbService: DynamodbService) {}

  async handleConnection(client: Socket) {
    let token;
    const cookies = client.handshake?.headers?.cookie;
    if (cookies) {
      const parsedCookies = cookie.parse(cookies);
      token = parsedCookies['access_token'];
    }
    // If no token found in the header, check cookies
    if (!token) {
      // Check for token in the Authorization header
      token =
        client.handshake?.auth?.token ||
        client.handshake?.headers?.authorization?.split(' ')[1];
    }

    // Ensure the client is authenticated before proceeding
    if (!token) {
      client.emit('error', 'Authentication required');
      client.disconnect();
      return;
    }
    this.clientDirectories.set(client.id, process.cwd()); // Default cwd

    // 🍑 System + Directory Info
    const info = {
      platform: os.platform(),
      type: os.type(),
      release: os.release(),
      arch: os.arch(),
      uptime: os.uptime(),
      hostname: os.hostname(),
      cwd: process.cwd(),
      homedir: os.homedir(),
    };

    // Convert uptime from seconds to a human-readable format (e.g., 1 day, 2 hours, 3 minutes)
    const convertUptimeToTime = (seconds: number) => {
      const days = Math.floor(seconds / (24 * 3600));
      const hours = Math.floor((seconds % (24 * 3600)) / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      const secs = Math.floor(seconds % 60);
      let uptimeString = '';
      if (days > 0) uptimeString += `${days} day${days > 1 ? 's' : ''}, `;
      if (hours > 0) uptimeString += `${hours} hour${hours > 1 ? 's' : ''}, `;
      if (minutes > 0)
        uptimeString += `${minutes} minute${minutes > 1 ? 's' : ''}, `;
      if (secs > 0) uptimeString += `${secs} second${secs > 1 ? 's' : ''}`;
      return uptimeString;
    };

    // Function to get system load, memory, and swap usage dynamically
    const sendSystemInfo = () => {
      exec('uptime', (err, stdout, stderr) => {
        if (err) {
          console.error('Error getting uptime:', stderr);
        } else {
          const systemLoad = stdout.split('load average: ')[1]?.split(',')[0]; // Parse system load

          exec('free -h', (err, stdout, stderr) => {
            if (err) {
              console.error('Error getting memory usage:', stderr);
            } else {
              const memoryUsage = stdout.split('\n')[1].split(/\s+/); // Memory usage
              const swapUsage = stdout.split('\n')[2].split(/\s+/); // Swap usage
              const uptimeString = convertUptimeToTime(info.uptime);

              const initMessage = `
Project Name: Bash AI

Smart Terminal AI is an intelligent, web-based terminal interface powered by NestJS and SolidJS, integrated with state-of-the-art AI models like ChatGPT and Google Gemini. This smart terminal allows users to interact with system commands, code snippets, and AI assistance in real-time—blending traditional shell-like functionality with natural language processing capabilities.

* Documentation:  https://github.com/evillan0315/bash-ai/docs
* Repo:     	  https://github.com/evillan0315/bash-ai

System information as of ${new Date().toUTCString()}

System load:  ${systemLoad}							Uptime:    ${uptimeString}		      
Memory usage: ${memoryUsage[2]} of ${memoryUsage[1]} (${memoryUsage[2]} used)	Hostname:  ${info.hostname}
Swap usage:   ${swapUsage[2]} of ${swapUsage[1]} (${swapUsage[2]} used)	Homedir:   ${info.homedir}                 		 
	
`;

              // Emit system info along with dynamic load and memory
              client.emit('outputMessage', initMessage);
            }
          });
        }
      });
    };

    // Send system info initially and then every 5 seconds
    sendSystemInfo();
    const intervalId = setInterval(sendSystemInfo, 5000); // Refresh system info every 5 seconds

    // Handle disconnection
    client.on('disconnect', () => {
      console.log(`Client disconnected: ${client.id}`);
      clearInterval(intervalId); // Stop sending updates when the client disconnects
      this.clientDirectories.delete(client.id);
    });
  }

  handleDisconnect(client: Socket) {
    this.clientDirectories.delete(client.id);
  }
  // 🧃 Client joins a room
  @SubscribeMessage('joinRoom')
  handleJoinRoom(client: Socket, roomId: string) {
    client.join(roomId);
    console.log(`[Room] ${client.id} joined room: ${roomId}`);

    client.emit('joinedRoom', {
      roomId,
      message: `You have joined room ${roomId}`,
    });

    // Optional: Notify others
    client.to(roomId).emit('userJoined', {
      userId: client.id,
      message: `A new user joined room ${roomId}`,
    });
  }
  @SubscribeMessage('exec')
  async handleCommand(
    @MessageBody() command: string,
    @ConnectedSocket() client: Socket,
  ) {
    let token;
    const cookies = client.handshake?.headers?.cookie;
    if (cookies) {
      const parsedCookies = cookie.parse(cookies);
      token = parsedCookies['access_token'];
    }

    if (!token) {
      // Check for token in the Authorization header or cookies
      token =
        client.handshake?.auth?.token ||
        client.handshake?.headers?.authorization?.split(' ')[1];
    }

    // Ensure the user is authenticated before processing the command
    if (!token) {
      client.emit('error', 'Authentication required');
      client.disconnect();
      return;
    }

    const clientId = client.id;
    let cwd = this.clientDirectories.get(clientId) || process.cwd();

    const user = client.data.user;
    //const commands = await this.dynamodbService.getStoredCommandsByUser(user.sub);

    //console.log(storedComm, 'storedComm');
    // Handle 'cd' separately
    if (command.startsWith('cd')) {
      const targetPath = command.slice(3).trim() || process.env.HOME || cwd;
      const newPath = resolve(cwd, targetPath);

      if (existsSync(newPath) && statSync(newPath).isDirectory()) {
        this.clientDirectories.set(clientId, newPath);
        cwd = newPath;
        client.emit('prompt', { cwd, command });
        client.emit('output', `Changed directory to ${newPath}\n`);
      } else {
        client.emit('prompt', { cwd, command });
        client.emit('error', `No such directory: ${newPath}\n`);
      }
      return;
    }

    const trimmedCmd = command.trim();
    client.emit('prompt', { cwd, command }); // Emit prompt info

    if (trimmedCmd === 'osinfo') {
      const info = {
        platform: os.platform(),
        type: os.type(),
        release: os.release(),
        arch: os.arch(),
        uptime: os.uptime(),
        hostname: os.hostname(),
        cwd: process.cwd(),
      };

      const output = Object.entries(info)
        .map(([key, val]) => `${key}: ${val}`)
        .join('\n');

      client.emit('output', output);
      return;
    }

    await this.dynamodbService.storeCommand(command, user.sub, user.username);

    const allCommandsResult = await this.dynamodbService.getStoredCommands();
    const allCommands = allCommandsResult.Items ?? [];

    const userCommands = allCommands
      .filter((cmd) => cmd.cognitoId?.S === client.data.user.sub)
      .map((cmd) => ({
        commandId: cmd.commandId.S,
        command: cmd.command.S,
        timestamp: cmd.timestamp.S,
        cognitoId: cmd.cognitoId.S,
        username: cmd.username?.S,
      }));
    console.log(`Client connected: ${user.username}`);
    client.emit('storedCommands', { user, userCommands });
    //client.emit('output', `Changed directory to ${newPath}\n`);
    const shell = spawn(command, {
      shell: '/bin/bash',
      cwd,
    });

    shell.stdout.on('data', (data) => {
      client.emit('output', data.toString());
    });

    shell.stderr.on('data', (data) => {
      client.emit('error', data.toString());
    });

    shell.on('close', (code) => {
      client.emit('close', `Process exited with code ${code}`);
    });
  }
}
