import { Injectable } from '@nestjs/common';
import {
  CostExplorerClient,
  GetCostAndUsageCommand,
  GetCostAndUsageCommandOutput,
} from '@aws-sdk/client-cost-explorer';
import {
  BudgetsClient,
  DescribeBudgetsCommand,
  DescribeBudgetsCommandOutput,
} from '@aws-sdk/client-budgets';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AwsBillingService {
  private costExplorerClient: CostExplorerClient;
  private budgetsClient: BudgetsClient;

  constructor(private readonly configService: ConfigService) {
    const region = this.configService.get('AWS_REGION'); // Use region from config
    const accessKeyId = this.configService.get('AWS_ACCESS_KEY_ID');
    const secretAccessKey = this.configService.get('AWS_SECRET_ACCESS_KEY');

    // Initialize AWS SDK clients with credentials from environment variables
    this.costExplorerClient = new CostExplorerClient({
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
    });

    this.budgetsClient = new BudgetsClient({
      region,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
    });
  }

  // Function to fetch cost and usage data
  async getCostAndUsage(startDate: string, endDate: string) {
    const command = new GetCostAndUsageCommand({
      TimePeriod: {
        Start: startDate,
        End: endDate,
      },
      Granularity: 'MONTHLY', // Granularity can be 'DAILY', 'MONTHLY', or 'HOURLY'
      Metrics: ['BlendedCost'], // You can change metrics to 'UnblendedCost', 'UsageQuantity', etc.
    });

    try {
      const data: GetCostAndUsageCommandOutput =
        await this.costExplorerClient.send(command);

      // Manually handle response data to match expected format
      const resultsByTime = data.ResultsByTime?.[0] ?? {};
      const totalCost = resultsByTime.Total ?? {};
      // Use the command parameters as fallbacks since the response structure might not match expectations
      const granularity = 'MONTHLY'; // Default to the value we sent in the command

      return {
        totalCost,
        granularity,
        startDate,
        endDate,
      };
    } catch (error) {
      throw new Error(`Error fetching cost and usage data: ${error.message}`);
    }
  }

  // Function to fetch budget details
  async getBudgetDetails() {
    const command = new DescribeBudgetsCommand({
      AccountId: this.configService.get('AWS_ACCOUNT_ID'),
    });

    try {
      const data: DescribeBudgetsCommandOutput =
        await this.budgetsClient.send(command);

      return data.Budgets ?? [];
    } catch (error) {
      throw new Error(`Error fetching budget details: ${error.message}`);
    }
  }
}
