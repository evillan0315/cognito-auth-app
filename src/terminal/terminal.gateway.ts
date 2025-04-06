import { UseGuards } from '@nestjs/common';
import { WebSocketGateway, WebSocketServer, SubscribeMessage, MessageBody, ConnectedSocket, OnGatewayConnection, OnGatewayDisconnect } from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { spawn } from 'child_process';
import * as os from 'os';
import * as process from 'process';
import { resolve } from 'path';
import { existsSync, statSync } from 'fs';
import { exec } from 'child_process';
import { CognitoWsGuard } from '../aws/cognito/cognito.ws.guard';
@WebSocketGateway({
  cors: {
    origin: ['http://localhost:5173'],
    credentials: true,
  },
})
@UseGuards(CognitoWsGuard)
export class TerminalGateway implements OnGatewayConnection, OnGatewayDisconnect {
  @WebSocketServer()
  server: Server;
  private clientDirectories: Map<string, string> = new Map();

  handleConnection(client: Socket) {
    // Ensure the client is authenticated before proceeding
    if (!client.handshake.auth || !client.handshake.auth.token) {
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
      if (minutes > 0) uptimeString += `${minutes} minute${minutes > 1 ? 's' : ''}, `;
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
              const swapUsage = stdout.split('\n')[2].split(/\s+/);   // Swap usage
              const uptimeString = convertUptimeToTime(info.uptime);

              const initMessage = `
Welcome to bashAI

* Documentation:  https://help.${info.platform.toLowerCase()}.com
* Management:     https://landscape.canonical.com
* Support:        https://${info.platform.toLowerCase()}.com/pro

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
    console.log(`Client disconnected: ${client.id}`);
    this.clientDirectories.delete(client.id);
  }

  @SubscribeMessage('exec')
  handleCommand(@MessageBody() command: string, @ConnectedSocket() client: Socket) {
    // Ensure the user is authenticated
    if (!client.handshake.auth || !client.handshake.auth.token) {
      client.emit('error', 'Authentication required');
      return;
    }

    const clientId = client.id;
    let cwd = this.clientDirectories.get(clientId) || process.cwd();

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

    // Emit the current directory before running

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

