import { Injectable, InternalServerErrorException } from '@nestjs/common';
import {
  CognitoIdentityProviderClient,
  AdminAddUserToGroupCommand,
  ListGroupsCommand,
  CreateGroupCommand,
  ListGroupsCommandOutput,
  CreateGroupCommandOutput,
  DeleteGroupCommandOutput,
  DeleteGroupCommand,
  AdminRemoveUserFromGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';

@Injectable()
export class RolesService {
  private readonly cognitoClient: CognitoIdentityProviderClient;

  constructor() {
    this.cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION,
    });
  }

  async addUserToGroup(username: string, groupName: string): Promise<void> {
    try {
      const group = await this.cognitoClient.send(
        new AdminAddUserToGroupCommand({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Username: username,
          GroupName: groupName,
        }),
      );
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to add user to group: ${error.message}`,
      );
    }
  }
  async removeUserFromGroup(
    username: string,
    groupName: string,
  ): Promise<void> {
    try {
      const response = await this.cognitoClient.send(
        new AdminRemoveUserFromGroupCommand({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Username: username,
          GroupName: groupName,
        }),
      );
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to remove user from group: ${error.message}`,
      );
    }
  }
  async listGroups(): Promise<ListGroupsCommandOutput['Groups']> {
    try {
      const response = await this.cognitoClient.send(
        new ListGroupsCommand({
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
        }),
      );

      return response.Groups || [];
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to list groups: ${error.message}`,
      );
    }
  }

  async createGroup(
    groupName: string,
    roleArn?: string,
    description?: string,
  ): Promise<CreateGroupCommandOutput> {
    try {
      const response = await this.cognitoClient.send(
        new CreateGroupCommand({
          GroupName: groupName,
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
          Description: description || 'No description provided', // Default description if none is provided
          Precedence: 1, // Set the priority for the group (higher precedence means higher priority)
          RoleArn: roleArn || undefined, // Assign the IAM Role to the group
        }),
      );
      console.log(`Group created with role: ${groupName}`);
      return response;
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to create group with role: ${error.message}`,
      );
    }
  }
  async deleteGroup(groupName: string): Promise<DeleteGroupCommandOutput> {
    try {
      const response = await this.cognitoClient.send(
        new DeleteGroupCommand({
          GroupName: groupName,
          UserPoolId: process.env.COGNITO_USER_POOL_ID,
        }),
      );
      console.log(`Group deleted: ${groupName}`);
      return response;
    } catch (error) {
      throw new InternalServerErrorException(
        `Failed to delete group: ${error.message}`,
      );
    }
  }
}
