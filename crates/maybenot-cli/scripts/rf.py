#!/usr/bin/env python3

"""
Runs Robust FingerPrinting (RF) by Shen et al., from the paper "Subverting
Website Fingerprinting Defenses with Robust Traffic Representation", USENIX
Security 2023.

The implementation below of RF is based on:

https://github.com/robust-fingerprinting/RF

Modified to work with our dataset structure and splitting.
"""

import argparse
import os
import sys
import numpy as np
import math
import torch
import torch.nn as nn
import torch.utils.data as Data
import torch.nn.functional as F
from torch.autograd import Variable
from multiprocessing import Pool
import datetime
import csv
import random

ap = argparse.ArgumentParser()
# dataset and its dimensions
ap.add_argument(
    "-d", required=True, default="", help="root folder of client/server dataset"
)
ap.add_argument(
    "-c",
    required=False,
    type=int,
    default=92,
    help="the number of monitored websites (=classes)",
)
ap.add_argument(
    "-p", required=False, type=int, default=10, help="the number of subpages"
)
ap.add_argument(
    "-s",
    required=False,
    type=int,
    default=20,
    help="the number of samples per subpage to load",
)
ap.add_argument(
    "-w",
    required=False,
    type=int,
    default=10,
    help="number of workers for loading traces from disk",
)

ap.add_argument(
    "--train", required=False, default=False, action="store_true", help="train model"
)
ap.add_argument(
    "--epochs",
    required=False,
    type=int,
    default=30,
    help="the number of epochs for training",
)
ap.add_argument(
    "--patience",
    required=False,
    type=int,
    default=10,
    help="the number of epochs for early stopping",
)

ap.add_argument("--sm", required=False, default="", help="save model to provided path")
ap.add_argument(
    "--lm", required=False, default="", help="load model from provided path"
)

## extra output
ap.add_argument(
    "--csv",
    required=False,
    default=None,
    help="save resulting metrics in provided path in csv format",
)
ap.add_argument(
    "--extra", required=False, default="", help="value of extra column in csv output"
)

# experiment parameters
ap.add_argument(
    "-f", required=False, type=int, default=0, help="the fold number (partition offset)"
)
ap.add_argument(
    "--seed", required=False, type=int, default=-1, help="seed for reproducibility"
)
args = vars(ap.parse_args())

EPOCH = 0
BATCH_SIZE = 200
LR = 0.0005


def now():
    return datetime.datetime.now().strftime("%H:%M:%S")


def main():
    if args["seed"] > -1:
        set_seed(args["seed"])
        print(f"{now()} using deterministic seed {args['seed']}")

    global EPOCH
    EPOCH = args["epochs"]
    print(f"{now()} using {EPOCH} epochs with patience {args['patience']}")

    dataset, labels = {}, {}
    if not os.path.isdir(args["d"]):
        sys.exit(f"{args['d']} is not a directory")

    print(f"{now()} starting to load dataset from {args['d']}")

    # check for dataset/0/0000-0000-0000.log or dataset/0/0.log
    subpages = os.path.exists(os.path.join(args["d"], "0", "0000-0000-0000.log"))
    samples = os.path.exists(os.path.join(args["d"], "0", "0.log"))
    if not subpages and not samples:
        sys.exit(f"{args['d']} does not contain subpages or samples")
    if subpages and samples:
        sys.exit(f"{args['d']} contains both subpages and samples")
    print(f"{now()} using subpages" if subpages else f"{now()} using samples")

    dataset, labels = load_dataset(
        args["d"], args["c"], None if samples else args["p"], args["s"], log2tam
    )

    print(f"{now()} loaded {len(dataset)} items in dataset with {len(labels)} labels")

    split = (
        split_dataset_samples(args["c"], args["s"], args["f"], labels)
        if samples
        else split_dataset_subpages(args["c"], args["p"], args["s"], args["f"], labels)
    )
    print(
        f"{now()} split {len(split['train'])} training and {len(split['test'])} testing"
    )

    #### Get data into expected format ####
    train_x = np.array([dataset[ID] for ID in split["train"]])
    train_y = np.array([labels[ID] for ID in split["train"]])
    test_x = np.array([dataset[ID] for ID in split["test"]])
    test_y = np.array([labels[ID] for ID in split["test"]])

    model = RF(args["c"])

    if args["lm"] != "":
        model = torch.load(args["lm"], weights_only=False)
        print(f"loaded model from {args['lm']}")

    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    if torch.cuda.is_available():
        print(f"{now()} using {torch.cuda.get_device_name(0)}")
        model.cuda()

    optimizer = torch.optim.Adam(params=model.parameters(), lr=LR, weight_decay=0.001)
    loss_func = torch.nn.CrossEntropyLoss()

    train_x = torch.unsqueeze(torch.from_numpy(train_x), dim=1).type(torch.FloatTensor)
    train_x = train_x.view(train_x.size(0), 1, 2, -1)
    train_y = torch.from_numpy(train_y).type(torch.LongTensor)

    train_data = Data.TensorDataset(train_x, train_y)
    train_loader = Data.DataLoader(
        dataset=train_data, batch_size=BATCH_SIZE, shuffle=True
    )

    # training
    if args["train"]:
        print(
            f"{now()} starting training with {args['epochs']} epochs and patience {args['patience']}"
        )
        model.train()
        best_loss = float("inf")
        patience = args["patience"]
        for epoch in range(EPOCH):
            print(f"{now()} epoch {epoch}")

            adjust_learning_rate(optimizer, epoch)
            running_loss = 0.0
            accuracy = 0.0
            n = 0
            for step, (tr_x, tr_y) in enumerate(train_loader):
                batch_x = Variable(tr_x.cuda())
                batch_y = Variable(tr_y.cuda())
                output = model(batch_x)
                _, a = get_result(output.cpu(), tr_y.cpu())

                del batch_x
                loss = loss_func(output, batch_y)
                del batch_y
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                running_loss += loss.item()
                accuracy += a
                n += 1

                del output

            print(f"\ttraining loss {running_loss / n:.4f}")
            print(f"\ttraining accuracy {accuracy / n:.4f}")
            if running_loss < best_loss:
                best_loss = running_loss
                patience = args["patience"]
            else:
                patience -= 1
                if patience == 0:
                    print(f"\tearly stopping, patience {args['patience']} reached")
                    break

        if args["sm"] != "":
            torch.save(model, args["sm"])
            print(f"saved model to {args['sm']}")

    # testing
    test_x = torch.unsqueeze(torch.from_numpy(test_x), dim=1).type(torch.FloatTensor)
    test_x = test_x.view(test_x.size(0), 1, 2, -1)
    test_x = test_x.to(device)
    test_y = torch.squeeze(torch.from_numpy(test_y)).type(torch.LongTensor)

    test_data = Data.TensorDataset(test_x, test_y)
    test_loader = Data.DataLoader(dataset=test_data, batch_size=1, shuffle=False)

    model.eval()
    predictions = []
    p_labels = []
    with torch.no_grad():
        for v, (x, y) in enumerate(test_loader):
            out = model(x)  # .cpu().squeeze().detach().numpy()
            index = F.softmax(out, dim=1).cpu().numpy()
            predictions.extend(index.tolist())
            p_labels.extend(y.data.numpy().tolist())

    print(f"{now()} made {len(predictions)} predictions with {len(p_labels)} labels")
    csvline = []
    threshold = np.append([0], 1.0 - 1 / np.logspace(0.05, 2, num=15, endpoint=True))
    threshold = np.around(threshold, decimals=4)
    for th in threshold:
        tp, fp, fn, accuracy, label_right, label_total = metrics(
            th, predictions, p_labels
        )
        print(
            f"\tthreshold {th:4.2}, "
            f"accuracy {accuracy:4.2}   "
            f"[tp {tp:>5}, fp {fp:>5}, fn {fn:>5}]"
        )
        if th == 0:
            print(f"\t\t", end="")
            n = 0
            for key, value in sorted(label_right.items(), key=lambda x: x[0]):
                r = value / label_total[key]
                print(f"{key:>2} {r:>5}, ", end=" ")
                n += 1
                if n == 10:
                    print("")
                    print(f"\t\t", end="")
                    n = 0
            print("")
        csvline.append([th, accuracy, tp, fp, fn, args["extra"]])

    if args["csv"]:
        with open(args["csv"], "w", newline="") as csvfile:
            w = csv.writer(csvfile, delimiter=",")
            w.writerow(["th", "accuracy", "tp", "fp", "fn", "extra"])
            w.writerows(csvline)
        print(f"saved testing results to {args['csv']}")

    tp, fp, fn, accuracy, label_right, label_total = metrics(0, predictions, p_labels)
    print(accuracy)


def parse_trace(fname, ID, extract_func):
    with open(fname, "r") as f:
        return (ID, extract_func(f.read()))


def load_dataset(folder, classes, subpages, samples, extract_func):
    """Loads the dataset from disk into two dictionaries for data and labels.

    If subpages is None, the dataset is loaded as samples per class. Otherwise,
    the dataset is loaded as subpages per class.
    """
    labels = {}

    # starmap into todo
    todo = []
    if subpages is None:
        for c in range(0, classes):
            for s in range(0, samples):
                ID = f"{c}-{s}"
                labels[ID] = c
                # file format is {sample}.log
                fname = f"{s}.log"
                todo.append((os.path.join(folder, str(c), fname), ID, extract_func))
    else:
        for c in range(0, classes):
            for p in range(0, subpages):
                for s in range(0, samples):
                    ID = to_file_label(c, p, s)
                    labels[ID] = c
                    # file format is {site}-{sample}.trace
                    fname = f"{ID}.log"
                    todo.append((os.path.join(folder, str(c), fname), ID, extract_func))

    # starmap do results
    p = Pool(args["w"])
    results = p.starmap(parse_trace, todo)

    # assemble results
    data = {}
    for result in results:
        features = np.array(result[1])
        if len(features.shape) < 3:
            features = features[:, np.newaxis, :]
        data[result[0]] = features

    return data, labels


def to_file_label(c, sub, sample):
    return f"{int(c):04d}-{int(sub):04d}-{int(sample):04d}"


def split_dataset_subpages(websites, subpages, samples, fold, labels):
    """Splits the dataset based on fold into 8:2.

    Splits based on subpages, not individual samples.
    """
    training = []
    testing = []

    # the split is made on subpages
    for c in range(0, websites):
        for p in range(0, subpages):
            for s in range(0, samples):
                ID = to_file_label(c, p, s)

                i = (p + fold) % subpages
                if i < subpages - 2:
                    training.append(ID)
                else:
                    testing.append(ID)

    split = {}
    split["train"] = training
    split["test"] = testing
    return split


def split_dataset_samples(classes, samples, fold, labels):
    """Splits the dataset based on fold into 8:2.

    Splits based on samples, not subpages.
    """
    training = []
    testing = []

    for c in range(0, classes):
        for s in range(0, samples):
            ID = f"{c}-{s}"

            i = (s + fold) % 10
            if i < 8:
                training.append(ID)
            else:
                testing.append(ID)

    split = {}
    split["train"] = training
    split["test"] = testing
    return split


def metrics(threshold, predictions, labels):
    """Computes a range of metrics.

    For details on the metrics, see, e.g., https://www.cs.kau.se/pulls/hot/baserate/
    """
    tp, fp, fn, accuracy = 0, 0, 0, 0.0

    # extended metric: per-class monitored stats
    label_right = {}
    label_total = {}

    for i in range(len(predictions)):
        label_pred = np.argmax(predictions[i])
        prob_pred = max(predictions[i])
        label_correct = labels[i]

        # total +1
        label_total[label_correct] = label_total.get(label_correct, 0) + 1

        # hack to get every label in the dict, not incrementing
        label_right[label_correct] = label_right.get(label_correct, 0)

        # either confident and correct,
        if prob_pred >= threshold and label_pred == label_correct:
            tp = tp + 1
            label_right[label_pred] = label_right.get(label_pred, 0) + 1
        # confident and wrong monitored label, or
        elif prob_pred >= threshold:
            fp = fp + 1
        # wrong because not confident enough
        else:
            fn = fn + 1

    accuracy = round(float(tp) / float(tp + fp + fn), 4)

    return tp, fp, fn, accuracy, label_right, label_total


max_matrix_len = 1800
maximum_load_time = 80.0


def log2tam(log):
    feature = [[0 for _ in range(max_matrix_len)], [0 for _ in range(max_matrix_len)]]

    s = log.split("\n")
    for line in s:
        parts = line.split(",")
        if len(parts) < 3:
            continue

        size = 1
        # turn time into seconds
        time = float(parts[0]) / float(1000 * 1000 * 1000)
        floc = 0 if "s" in parts[1] else 1 if "r" in parts[1] else -1

        if floc > -1:
            if time >= maximum_load_time:
                feature[floc][-1] += size
            else:
                idx = int(time * (max_matrix_len - 1) / maximum_load_time)
                feature[floc][idx] += size

    return feature


def adjust_learning_rate(optimizer, echo):
    lr = LR * (0.2 ** (echo / EPOCH))
    for para_group in optimizer.param_groups:
        para_group["lr"] = lr


def get_result(output, true_y):
    pred_y = torch.max(output, 1)[1].data.numpy().squeeze()
    accuracy = (pred_y == true_y.numpy()).sum().item() * 1.0 / float(true_y.size(0))
    return pred_y, accuracy


# from https://github.com/Xinhao-Deng/Website-Fingerprinting-Library/blob/master/WFlib/models/RF.py
class RF(nn.Module):
    def __init__(self, num_classes=100, num_tab=1):
        """
        Initialize the RF model.

        Parameters:
        num_classes (int): Number of output classes.
        num_tab (int): Number of tabs (not used in this model).
        """
        super(RF, self).__init__()

        # Create feature extraction layers
        features = make_layers([128, 128, "M", 256, 256, "M", 512] + [num_classes])
        init_weights = True
        self.first_layer_in_channel = 1
        self.first_layer_out_channel = 32

        # Create the initial convolutional layers
        self.first_layer = make_first_layers()
        self.features = features
        self.class_num = num_classes

        # Adaptive average pooling layer for classification
        self.classifier = nn.AdaptiveAvgPool1d(1)

        # Fully connected layer to project to embedding space
        self.to_emb = nn.Sequential(
            nn.Flatten(),
            nn.Linear(in_features=num_classes * 65, out_features=128),
        )

        # Initialize weights
        if init_weights:
            self._initialize_weights()

    def forward(self, x):
        """
        Forward pass of the model.

        Parameters:
        x (Tensor): Input tensor.

        Returns:
        Tensor: Output tensor after passing through the network.
        """
        x = self.first_layer(x)
        x = x.view(x.size(0), self.first_layer_out_channel, -1)
        x = self.features(x)
        x = self.classifier(x)
        x = x.view(x.size(0), -1)
        return x

    def _initialize_weights(self):
        """
        Initialize weights for the network layers.
        """
        for m in self.modules():
            if isinstance(m, nn.Conv2d):
                n = m.kernel_size[0] * m.kernel_size[1] * m.out_channels
                m.weight.data.normal_(0, math.sqrt(2.0 / n))
                if m.bias is not None:
                    m.bias.data.zero_()
            elif isinstance(m, nn.BatchNorm2d):
                m.weight.data.fill_(1)
                m.bias.data.zero_()
            elif isinstance(m, nn.Linear):
                m.weight.data.normal_(0, 0.01)
                m.bias.data.zero_()


def make_layers(cfg, in_channels=32):
    """
    Create a sequence of convolutional and pooling layers.

    Parameters:
    cfg (list): Configuration list specifying the layers.
    in_channels (int): Number of input channels.

    Returns:
    nn.Sequential: Sequential container with the layers.
    """
    layers = []

    for v in cfg:
        if v == "M":
            layers += [nn.MaxPool1d(3), nn.Dropout(0.3)]
        else:
            conv1d = nn.Conv1d(in_channels, v, kernel_size=3, stride=1, padding=1)
            layers += [
                conv1d,
                nn.BatchNorm1d(v, eps=1e-05, momentum=0.1, affine=True),
                nn.ReLU(),
            ]
            in_channels = v

    return nn.Sequential(*layers)


def make_first_layers(in_channels=1, out_channel=32):
    """
    Create the initial convolutional layers.

    Parameters:
    in_channels (int): Number of input channels.
    out_channel (int): Number of output channels.

    Returns:
    nn.Sequential: Sequential container with the initial layers.
    """
    layers = []
    conv2d1 = nn.Conv2d(
        in_channels, out_channel, kernel_size=(3, 6), stride=1, padding=(1, 1)
    )
    layers += [
        conv2d1,
        nn.BatchNorm2d(out_channel, eps=1e-05, momentum=0.1, affine=True),
        nn.ReLU(),
    ]

    conv2d2 = nn.Conv2d(
        out_channel, out_channel, kernel_size=(3, 6), stride=1, padding=(1, 1)
    )
    layers += [
        conv2d2,
        nn.BatchNorm2d(out_channel, eps=1e-05, momentum=0.1, affine=True),
        nn.ReLU(),
    ]

    layers += [nn.MaxPool2d((1, 3)), nn.Dropout(0.1)]

    conv2d3 = nn.Conv2d(out_channel, 64, kernel_size=(3, 6), stride=1, padding=(1, 1))
    layers += [
        conv2d3,
        nn.BatchNorm2d(64, eps=1e-05, momentum=0.1, affine=True),
        nn.ReLU(),
    ]

    conv2d4 = nn.Conv2d(64, 64, kernel_size=(3, 6), stride=1, padding=(1, 1))
    layers += [
        conv2d4,
        nn.BatchNorm2d(64, eps=1e-05, momentum=0.1, affine=True),
        nn.ReLU(),
    ]

    layers += [nn.MaxPool2d((2, 2)), nn.Dropout(0.1)]

    return nn.Sequential(*layers)


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)  # if using multi-GPU
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


if __name__ == "__main__":
    main()
