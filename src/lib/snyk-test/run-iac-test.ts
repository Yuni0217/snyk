import * as fs from 'fs';
import * as path from 'path';
import * as pathUtil from 'path';
import { TestResult } from './legacy';
import { IacTestResponse } from './iac-test-result';
import * as snyk from '..';
import { isCI } from '../is-ci';
import * as common from './common';
import * as config from '../config';
import { Options, TestOptions } from '../types';
import { Payload } from './types';
import { IacScan } from './payload-schema';
import { SEVERITY } from './legacy';
import * as pathLib from 'path';
import { projectTypeByFileType, IacFileTypes } from '../iac/constants';

export async function parseIacTestResult(
  res: IacTestResponse,
  targetFile: string | undefined,
  projectName: any,
  severityThreshold?: SEVERITY,
  //TODO(orka): future - return a proper type
): Promise<TestResult> {
  const meta = (res as any).meta || {};

  severityThreshold =
    severityThreshold === SEVERITY.LOW ? undefined : severityThreshold;

  return {
    ...res,
    vulnerabilities: [],
    dependencyCount: 0,
    licensesPolicy: null,
    ignoreSettings: null,
    targetFile,
    projectName,
    org: meta.org,
    policy: meta.policy,
    isPrivate: !meta.isPublic,
    severityThreshold,
  };
}

export interface IacPayloadFile {
  fileType: string;
  targetFile: string;
  targetFileRelativePath: string;
}

export async function assembleIacLocalPayloads(
  root: string,
  options: Options & TestOptions,
): Promise<Payload[]> {
  const filesToTest: IacPayloadFile[] = [];

  if (!options.iacDirFiles) {
    const fileType = pathLib.extname(root).substr(1);
    const targetFile = pathLib.resolve(root, '.');
    const targetFileRelativePath = targetFile
      ? pathUtil.join(pathUtil.resolve(`${options.path}`), targetFile)
      : '';
    filesToTest.push({ fileType, targetFile, targetFileRelativePath });
  } else {
    for (const iacFile of options.iacDirFiles) {
      if (iacFile.projectType) {
        const targetFile = iacFile.filePath;
        filesToTest.push({
          fileType: iacFile.fileType,
          targetFile,
          targetFileRelativePath: targetFile,
        });
      }
    }
  }

  return filesToTest.map((iacFile) => {
    return assembleIacLocalPayload(
      iacFile.fileType,
      iacFile.targetFile,
      iacFile.targetFileRelativePath,
      options,
    );
  });
}

function assembleIacLocalPayload(
  fileType: string,
  targetFile: string,
  targetFileRelativePath: string,
  options: Options & TestOptions,
): Payload {
  const fileContent = fs.readFileSync(targetFile, 'utf8');
  const projectType = projectTypeByFileType[fileType];

  const body: IacScan = {
    data: {
      fileContent,
      fileType: fileType as IacFileTypes,
    },
    targetFile,
    type: projectType,
    //TODO(orka): future - support policy
    policy: '',
    targetFileRelativePath: `${targetFileRelativePath}`, // Forcing string
    originalProjectName: path.basename(path.dirname(targetFile)),
    projectNameOverride: options.projectName,
  };
  const payload: Payload = {
    method: 'POST',
    url: config.API + (options.vulnEndpoint || '/test-iac'),
    json: true,
    headers: {
      'x-is-ci': isCI(),
      authorization: 'token ' + (snyk as any).api,
    },
    qs: common.assembleQueryString(options),
    body,
  };

  return payload;
}
