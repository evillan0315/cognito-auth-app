import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { AwsBillingService } from './aws-billing.service';
import {
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { CostAndUsageResponse } from './aws-billing.dto';
import { Roles } from '../admin/roles/roles.decorator'; // Ensure correct path
import { Role } from '../admin/roles/role.enum'; // Ensure correct path
import { RolesGuard } from '../admin/roles/roles.guard'; // Ensure correct path
import { CognitoGuard } from '../aws/cognito/cognito.guard'; // Adjust the path as needed

@ApiTags('AWS - Billing') // Updated Swagger grouping
@ApiBearerAuth() // Requires authentication via Bearer token
@UseGuards(CognitoGuard, RolesGuard)
@Controller('billing')
export class AwsBillingController {
  constructor(private readonly awsBillingService: AwsBillingService) {}

  @Get('cost-usage')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Get AWS Cost and Usage' })
  @ApiResponse({
    status: 200,
    description: 'The cost and usage data was successfully retrieved.',
    type: CostAndUsageResponse,
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to retrieve cost and usage data.',
  })
  async getCostAndUsage(
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
  ): Promise<CostAndUsageResponse> {
    const awsResponse = await this.awsBillingService.getCostAndUsage(
      startDate,
      endDate,
    );

    // Log the AWS response for debugging
    console.log(awsResponse); // Inspect the structure of awsResponse

    // Safely map the response data to the DTO
    const costAndUsageResponse: CostAndUsageResponse = {
      TotalCost: awsResponse.totalCost || {}, // Use the property from the service response
      Granularity: awsResponse.granularity || 'MONTHLY',
      StartDate: awsResponse.startDate || startDate,
      EndDate: awsResponse.endDate || endDate,
    };

    return costAndUsageResponse;
  }

  @Get('budgets')
  @Roles(Role.ADMIN, Role.SUPERADMIN) // Restrict to Admins
  @ApiOperation({ summary: 'Get AWS Budget details' })
  @ApiResponse({
    status: 200,
    description: 'The budget details were successfully retrieved.',
  })
  @ApiResponse({
    status: 500,
    description: 'Failed to retrieve budget details.',
  })
  async getBudgetDetails() {
    return this.awsBillingService.getBudgetDetails();
  }
}
