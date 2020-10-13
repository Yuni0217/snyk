export type IacProjectTypes =
  | 'k8sconfig'
  | 'terraformconfig'
  | 'multiiacconfig';
export type IacFileTypes = 'yaml' | 'yml' | 'json' | 'tf';

export enum IacProjectType {
  K8S = 'k8sconfig',
  TERRAFORM = 'terraformconfig',
  MULTI_IAC = 'multiiacconfig',
}

export const TEST_SUPPORTED_IAC_PROJECTS: IacProjectTypes[] = [
  IacProjectType.K8S,
  IacProjectType.TERRAFORM,
  IacProjectType.MULTI_IAC,
];

export const projectTypeByFileType = {
  yaml: IacProjectType.K8S,
  yml: IacProjectType.K8S,
  json: IacProjectType.K8S,
  tf: IacProjectType.TERRAFORM,
};

export type IacValidateTerraformResponse = {
  body?: {
    isValidTerraformFile: boolean;
    reason: string;
  };
};

export interface IacValidationResponse {
  isValidFile: boolean;
  reason: string;
}
