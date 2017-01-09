#!/usr/bin/env python3
"""
RDS Functions
"""

import sys
from datetime import datetime, timedelta
from exclusions import excluded_instances
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
    while 'Marker' in resp:
        rds_instances.extend(resp['DBInstances'])
        resp = client.describe_db_instances(Marker=resp['Marker'])
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
        sec_groups = client.describe_security_groups(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc]
                },
                {
                    "Name": "group-name",
                    "Values": ["rds-isolate"]
                }
            ]
        )['SecurityGroups']
        try:
            isolated_sgs[vpc] = sec_groups[0]['GroupId']
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
        DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
        MultiAZ=False,
        ApplyImmediately=True
    )

def set_security_group(client, rds_instance, sg_id):
    " Sets the rds_instance Security Group to sg_id "
    client.modify_db_instance(
        DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
        VpcSecurityGroupIds=[sg_id]
    )

def set_instance_size(client, rds_instance, size=None):
    " Sets instance to the smallest available size "
    if not size:
        available_sizes = client.describe_orderable_db_instance_options(
            Engine=rds_instance['Engine']
        )['OrderableDBInstanceOptions']
        size = available_sizes[0]['DBInstanceClass']

    client.modify_db_instance(
        DBInstanceIdentifier=rds_instance['DBInstanceIdentifier'],
        DBInstanceClass=size,
        ApplyImmediately=True
    )

def main():
    " Main execution "
    debug = True
    dry_run = True
    session = get_session('', '')
    ec2 = get_ec2_client(session)
    rds = get_rds_client(session)
    cloudwatch = get_cloudwatch_client(session)

    isolated_sgs = get_isolated_sgs(ec2)
    all_rds_instances = get_rds_instances(rds)
    all_rds_stats = get_connections_statistics(cloudwatch, all_rds_instances)
    if debug:
        print("DEBUG: Isolated SGs {}".format(isolated_sgs))
        print("DEBUG: All RDS Instances :")
        for instance in all_rds_instances:
            print(instance['DBInstanceIdentifier'])
    abandoned_instances = []
    for key in all_rds_stats:
        if all_rds_stats[key] == 0 and key not in excluded_instances:
            abandoned_instances.append(key)
        elif all_rds_stats[key] == 0 and key in excluded_instances:
            print("%s meets low connections criteria, but has been excluded." % key)
        if debug:
            print("DEBUG: Instance: %s. Connections: %s" % (key, all_rds_stats[key]))
    if len(abandoned_instances) > 0:
        print("\nThe following instances appear to be abandoned. Please investigate.")
        for instance in abandoned_instances:
            print(instance)
    else:
        print("\nNo instances appear to be abandoned.")
        sys.exit(0)
    print("\nTaking action on the following instances: ")
    for rds_instance in all_rds_instances:
        if rds_instance['DBInstanceIdentifier'] in abandoned_instances:
            if dry_run:
                print("DRYRUN: %s would have been isolated and downsized."
                      % rds_instance['DBInstanceIdentifier'])
            else:
                print("Isolating and downsizing instance: %s"
                      % rds_instance['DBInstanceIdentifier'])
                set_security_group(rds,
                                   rds_instance,
                                   isolated_sgs[rds_instance['DBSubnetGroup']['VpcId']])

                set_instance_size(rds,
                                  rds_instance,
                                  'db.t2.micro')

                set_no_multiaz(rds, rds_instance)

main()
