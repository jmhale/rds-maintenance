#!/usr/bin/env python3
"""
RDS Functions
"""

from datetime import datetime, timedelta
import boto3

def get_session(access_key_id, secret_access_key):
    " Establishes a session with AWS "
    return boto3.session.Session(
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key
    )

def get_rds_client(session):
    " Returns a RDS boto client "
    return session.client('rds')

def get_cloudwatch_client(session):
    " Returns a CloudWatch boto client "
    return session.client('cloudwatch')

def get_ec2_client(session):
    " Returns a EC2 boto client "
    return session.client('ec2')

def get_rds_instances(client, vpc_id=None):
    " Gets all RDS instances, per VPC, if specified. "

    rds_instances = []
    resp = client.describe_db_instances()
    while 'NextToken' in resp:
        rds_instances.extend(resp['DBInstances'])
        resp = client.describe_db_instances(NextToken=resp['NextToken'])
    rds_instances.extend(resp['DBInstances'])

    if not vpc_id:
        return rds_instances
    else:
        return [r for r in rds_instances if r['DBSubnetGroup.VpcId'].equals(vpc_id)]

def get_vpc_ids(client):
    " Returns a list of VPC IDs in the account "
    vpc_ids = []
    vpcs = client.describe_vpcs()['Vpcs']
    for vpc in vpcs:
        vpc_ids.append(vpc['VpcId'])
    return vpc_ids

def get_isolated_sgs(client):
    " Returns a dict of rds-isolate SG IDs for each VPC in account. "
    vpc_ids = get_vpc_ids(client)
    isolated_sgs = {}
    for vpc in vpc_ids:
        sg = client.describe_security_groups(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc]
                },
                {
                    "Name": "tag:Name",
                    "Values": ["rds-isolate"]
                }
            ]
        )['SecurityGroups']
        try:
            isolated_sgs[vpc] = sg[0]['GroupId']
        except IndexError:
            print("No rds-isolate group found for VPC: {}".format(vpc))
    return isolated_sgs

def get_connections_statistics(client, rds_instances):
    " Returns a dict of all instances and their avg DB conns over all datapoints "
    rds_stats = {}
    for rds_instance in rds_instances:
        stats = client.get_metric_statistics(
            Namespace="AWS/RDS",
            MetricName="DatabaseConnections",
            Statistics=['Average'],
            Period=57600,
            StartTime=(datetime.today() - timedelta(days=3)),
            EndTime=datetime.today(),
            Dimensions=[
                {
                    'Name': 'DBInstanceIdentifier',
                    'Value': rds_instance['DBInstanceIdentifier']
                }
            ]
        )['Datapoints']
        datapoints = []
        for stat in stats:
            datapoints.append(stat['Average'])
        dp_conns = sum(datapoints)/float(len(datapoints))
        rds_stats[rds_instance['DBInstanceIdentifier']] = dp_conns

        return rds_stats

def set_no_multiaz(client, rds_instance):
    " Takes a rds instance obj and turns off MultiAZ "
    client.modify_db_instance(
        DBInstanceIdentifer=rds_instance['DBInstanceIdentifer'],
        MultiAZ=False,
        ApplyImmediately=True
    )

##TODO: See if we can set SG to empty set
def set_security_group(client, rds_instance, sg_id):
    " Sets the rds_instance Security Group to sg_id "
    client.modify_db_instance(
        DBInstanceIdentifer=rds_instance['DBInstanceIdentifer'],
        VpcSecurityGroupIds=[sg_id]
        # VpcSecurityGroupIds=[]
    )

##TODO: See if this outputs in a reliable order. Maybe we can just take the 0 index as the smallest.
def set_instance_size(client, rds_instance, size=None):
    " Sets instance to the smallest available size "
    if not size:
        available_sizes = client.describe_orderable_db_instance_options(
            Engine=rds_instance['Engine']
        )['OrderableDBInstanceOptions']
        size = available_sizes[0]['DBInstanceClass']

    client.modify_db_instance(
        DBInstanceIdentifer=rds_instance['DBInstanceIdentifer'],
        DBInstanceClass=size,
        ApplyImmediately=True
    )

def main():
    " Main execution "
    session = get_session('', '')
    ec2 = get_ec2_client(session)
    rds = get_rds_client(session)
    cloudwatch = get_cloudwatch_client(session)

    print("DEBUG: Isolated SGs {}".format(get_isolated_sgs(ec2)))
    all_rds_instances = get_rds_instances(rds)
    print("DEBUG: All RDS Instances {}".format(all_rds_instances[0]['DBInstanceIdentifier']))
    all_rds_stats = get_connections_statistics(cloudwatch, all_rds_instances)
    print("DEBUG: All RDS Stats {}".format(all_rds_stats))

main()
